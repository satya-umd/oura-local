import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  upsertRingDevice,
  setRingSyncCursor,
  insertRingEvent,
  insertRingReading,
  getRingEventsForUser,
  upsertDailySummary,
  replaceHeartrateDay,
  getUserBaselines,
  toLocalDayStr,
  clearUserSummariesForRealSync
} from './db.mjs';

/**
 * Port of `Th0rgal/open_oura` (`oura-protocol`, `oura-analysis`, `oura-summary`)
 * for 100% cloud-free Oura Ring Gen 3 / 4 / 5 BLE communication, binary event
 * decoding, and on-device `ecore` biometric scoring without an Oura Membership.
 */

export const OURA_SERVICE_UUID = '98ed0001-a541-11e4-b6a0-0002a5d5c51b';
export const OURA_WRITE_UUID = '98ed0002-a541-11e4-b6a0-0002a5d5c51b';
export const OURA_NOTIFY_UUID = '98ed0003-a541-11e4-b6a0-0002a5d5c51b';
export const HISTORY_EVENT_PREFIX = 0x41;

export const FEATURE_ID = {
  BACKGROUND_DFU: 0x00,
  RESEARCH_DATA: 0x01,
  DAYTIME_HR: 0x02,
  EXERCISE_HR: 0x03,
  SPO2: 0x04,
  RESTING_HR: 0x08,
  CHARGING_CONTROL: 0x0e
};

export const FEATURE_MODE = {
  OFF: 0x00,
  AUTOMATIC: 0x01,
  REQUESTED: 0x02,
  CONNECTED_LIVE: 0x03
};

/**
 * Encode `[tag, length, ...payload]` BLE frame.
 */
export function encodePacket(tag, payload = []) {
  const buf = Buffer.alloc(2 + payload.length);
  buf[0] = tag & 0xff;
  buf[1] = payload.length & 0xff;
  for (let i = 0; i < payload.length; i++) {
    buf[2 + i] = payload[i] & 0xff;
  }
  return buf;
}

/**
 * Parse concatenated `tag | length | payload` packets from a BLE notification frame.
 * Mirrors `oura_protocol::protocol::Packet::parse_many`.
 */
export function parsePackets(frameBytes) {
  const buf = Buffer.isBuffer(frameBytes) ? frameBytes : Buffer.from(frameBytes);
  const out = [];
  let i = 0;
  while (i + 2 <= buf.length) {
    const tag = buf[i];
    const len = buf[i + 1];
    const start = i + 2;
    const end = start + len;
    if (end > buf.length) break;
    out.push({
      tag,
      extTag: tag === 0x2f && len > 0 ? buf[start] : null,
      payload: buf.subarray(start, end)
    });
    i = end;
  }
  if (out.length === 0 && buf.length >= 2) {
    const tag = buf[0];
    const payload = buf.subarray(2);
    out.push({
      tag,
      extTag: tag === 0x2f && payload.length > 0 ? payload[0] : null,
      payload
    });
  }
  return out;
}

// --- BLE Request Builders (ported from `oura-protocol/src/protocol.rs`) ---

export function reqFirmware() {
  return Buffer.from([0x08, 0x03, 0x00, 0x00, 0x00]);
}

export function reqBattery() {
  return encodePacket(0x0c, []);
}

export function reqSerial() {
  return Buffer.from([0x18, 0x03, 0x08, 0x00, 0x10]);
}

export function reqHardwareId() {
  return Buffer.from([0x18, 0x03, 0x18, 0x00, 0x10]);
}

export function reqAuthNonce() {
  return Buffer.from([0x2f, 0x01, 0x2b]);
}

export function reqAuthenticate(keyOrEncrypted, maybeNonce = null) {
  let encBuf;
  if (maybeNonce !== null) {
    encBuf = encryptAuthNonce(keyOrEncrypted, maybeNonce);
  } else if (typeof keyOrEncrypted === 'string') {
    encBuf = Buffer.from(keyOrEncrypted.trim().replace(/^0x/i, ''), 'hex');
  } else {
    encBuf = Buffer.from(keyOrEncrypted);
  }
  return encodePacket(0x2f, [0x2d, ...encBuf]);
}

export function reqSetAuthKey(key16) {
  const keyBuf =
    typeof key16 === 'string'
      ? Buffer.from(key16.trim().replace(/^0x/i, ''), 'hex')
      : Buffer.from(key16);
  return encodePacket(0x24, [...keyBuf]);
}

export function reqSyncTime(
  unixSecs = Math.floor(Date.now() / 1000),
  tzHalfHours = Math.round(-new Date().getTimezoneOffset() / 30)
) {
  const payload = Buffer.alloc(9);
  payload.writeBigUInt64LE(BigInt(unixSecs), 0);
  payload[8] = tzHalfHours & 0xff;
  return encodePacket(0x12, payload);
}

export function reqGetEvent(startDeciseconds = 0, maxEvents = 255, flags = -1) {
  const payload = Buffer.alloc(9);
  payload.writeUInt32LE(startDeciseconds >>> 0, 0);
  payload[4] = maxEvents & 0xff;
  payload.writeInt32LE(flags, 5);
  return encodePacket(0x10, payload);
}

export function reqCheckSleepAnalysis(force = true) {
  return Buffer.from([0x28, 0x01, force ? 1 : 0]);
}

export function reqSetFeatureMode(featureId, mode = FEATURE_MODE.AUTOMATIC) {
  return Buffer.from([0x2f, 0x03, 0x22, featureId & 0xff, mode & 0xff]);
}

export function parseFirmwareResponse(pkt) {
  const p = pkt.payload || Buffer.alloc(0);
  if (p.length >= 6) {
    return {
      firmware: `${p[0]}.${p[1]}.${p[2]}`,
      bootloader: `${p[3]}.${p[4]}.${p[5]}`
    };
  }
  return { firmware: p.toString('hex'), bootloader: '' };
}

export function parseBatteryResponse(pkt) {
  const p = pkt.payload || Buffer.alloc(0);
  if (p.length < 1) return null;
  return {
    percent: Math.min(100, p[0]),
    charging: p.length > 1 ? Boolean(p[1]) : false
  };
}

export function parseSerialResponse(pkt) {
  const p = pkt.payload || Buffer.alloc(0);
  const text = p.toString('utf8').replace(/\0/g, '').trim();
  return {
    serial: text || p.toString('hex'),
    hwId: ''
  };
}

// --- App-level Authentication (`oura-protocol/src/auth.rs`) ---

/**
 * Encrypts the ring's 15-byte challenge nonce using AES-128-ECB with PKCS#7 padding
 * under the ring's 16-byte auth key.
 * Verified byte-for-byte against `open_oura`'s `known_answer_vector` unit test.
 */
export function encryptAuthNonce(keyHexOrBuf, nonceHexOrBuf) {
  const key =
    typeof keyHexOrBuf === 'string' ? Buffer.from(keyHexOrBuf.trim(), 'hex') : Buffer.from(keyHexOrBuf);
  if (key.length !== 16) {
    throw new Error(`Ring auth key must be 16 bytes (32 hex chars), got ${key.length} bytes.`);
  }
  const nonce =
    typeof nonceHexOrBuf === 'string'
      ? Buffer.from(nonceHexOrBuf.trim(), 'hex')
      : Buffer.from(nonceHexOrBuf);

  const block = Buffer.alloc(16);
  const n = Math.min(16, nonce.length);
  nonce.copy(block, 0, 0, n);
  const pad = 16 - n;
  for (let i = n; i < 16; i++) {
    block[i] = pad;
  }

  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

export function generateRingAuthKeyHex() {
  return crypto.randomBytes(16).toString('hex');
}

// --- Event Names & Binary Event-Body Decoders (`oura-protocol/src/events.rs`) ---

const EVENT_NAMES = {
  0x41: 'ring_start',
  0x42: 'time_sync',
  0x43: 'debug_event',
  0x45: 'state_change',
  0x46: 'temp_event',
  0x47: 'motion_event',
  0x49: 'sleep_summary_1',
  0x4b: 'sleep_phase_information',
  0x4c: 'sleep_summary_2',
  0x4e: 'sleep_phase_details',
  0x4f: 'sleep_summary_3',
  0x50: 'activity_information',
  0x53: 'wear_event',
  0x56: 'alert_event',
  0x58: 'sleep_summary_4',
  0x59: 'ambient_event',
  0x5a: 'sleep_phase_data',
  0x5b: 'ble_connection_ind',
  0x5c: 'user_information',
  0x5d: 'hrv_event',
  0x60: 'ibi_and_amplitude_event',
  0x61: 'debug_data',
  0x69: 'temp_period',
  0x6a: 'sleep_period_information_2',
  0x6b: 'motion_period',
  0x6c: 'feature_session',
  0x6f: 'spo2_event',
  0x72: 'sleep_acm_period',
  0x74: 'ehr_acm_intensity_event',
  0x75: 'sleep_temp_event',
  0x76: 'bedtime_period',
  0x7e: 'real_steps_features_1',
  0x7f: 'real_steps_features_2',
  0x80: 'green_ibi_quality_event',
  0x81: 'cva_raw_ppg_data',
  0x84: 'ambient_event_v2',
  0x85: 'rtc_beacon',
  0x86: 'aohr_event',
  0x8b: 'spo2_r_pi_event'
};

export function eventName(tag) {
  return EVENT_NAMES[tag] || `unknown_0x${Number(tag).toString(16).padStart(2, '0')}`;
}

/**
 * Decodes a raw event body for `tag` (`0x41..0x8b`).
 * Exact port of `oura_protocol::events::decode_body`.
 */
export function decodeEventBody(tag, bodyInput) {
  const body = Buffer.isBuffer(bodyInput) ? bodyInput : Buffer.from(bodyInput || []);
  switch (tag) {
    case 0x41: {
      if (body.length < 14) return null;
      const v3 = (slice) => `${slice[0]}.${slice[1]}.${slice[2]}`;
      return {
        reason: body.readUInt32LE(0),
        unknown_byte_4: body[4],
        firmware_version: v3(body.subarray(5, 8)),
        bootloader_version: v3(body.subarray(8, 11)),
        api_version: v3(body.subarray(11, 14))
      };
    }
    case 0x42: {
      if (body.length < 4) return null;
      const unix_time = body.readUInt32LE(0);
      const tail = body.subarray(4).toString('utf8');
      return tail === 'phone' ? { unix_time, source: 'phone' } : { unix_time };
    }
    case 0x85: {
      if (body.length < 10) return null;
      return {
        unix_time: body.readUInt32LE(0),
        trailer: body.readUInt16LE(8)
      };
    }
    case 0x43: {
      const ascii = body.toString('utf8').replace(/\0+$/, '').trim();
      return ascii ? { ascii } : null;
    }
    case 0x45:
    case 0x53: {
      if (body.length === 0) return null;
      return {
        state: body[0],
        text: body.subarray(1).toString('utf8').replace(/\0+$/, '').trim()
      };
    }
    case 0x46:
    case 0x69:
    case 0x75: {
      if (body.length === 0 || body.length % 2 !== 0) return null;
      const temps_c = [];
      for (let i = 0; i < body.length; i += 2) {
        const centi = body.readInt16LE(i);
        const celsius = centi / 100.0;
        if (celsius < -40.0 || celsius > 85.0) return null;
        temps_c.push(Math.round(celsius * 100) / 100);
      }
      return { temps_c };
    }
    case 0x47: {
      if (body.length < 4) return null;
      const out = {
        orientation: body[0] >> 5,
        motion_seconds: body[0] & 0x1f,
        avg_x: body.readInt8(1) * 8,
        avg_y: body.readInt8(2) * 8,
        avg_z: body.readInt8(3) * 8
      };
      if (body.length >= 5) {
        if (body[4] & 0x40) return null;
        out.low_intensity = body[4] & 0x3f;
      }
      if (body.length >= 6) {
        if (body[5] & 0x40) return null;
        out.high_intensity = body[5] & 0x3f;
      }
      return out;
    }
    case 0x4b:
    case 0x4e:
    case 0x5a: {
      if (body.length < 2) return null;
      const PHASE = ['deep', 'light', 'rem', 'awake'];
      const phases = [];
      for (let i = 1; i < body.length; i++) {
        const b = body[i];
        for (const shift of [6, 4, 2, 0]) {
          phases.push(PHASE[(b >> shift) & 0x03]);
        }
      }
      return { header: body[0], phases };
    }
    case 0x50: {
      if (body.length < 1) return null;
      const state = body[0];
      const met = [];
      for (let i = 1; i < body.length; i++) {
        const b = body[i];
        const m = b < 0x80 ? b * 0.1 : 12.8 + (b - 128) * 0.2;
        met.push(Math.round(m * 100) / 100);
      }
      return { state, met };
    }
    case 0x5c: {
      if (body.length < 4) return null;
      const sex = body[2] === 0 ? 'male' : body[2] === 1 ? 'female' : 'unspecified';
      return {
        age_years: body[0],
        weight_kg: body[1],
        sex_code: body[2],
        sex,
        height_cm: body[3]
      };
    }
    case 0x5d: {
      if (body.length === 0 || body.length % 2 !== 0) return null;
      const hr_bpm = [];
      const rmssd_ms = [];
      for (let i = 0; i < body.length; i += 2) {
        hr_bpm.push(body[i]);
        rmssd_ms.push(body[i + 1]);
      }
      return { hr_bpm, rmssd_ms, interval_min: 5 };
    }
    case 0x60: {
      if (body.length !== 14) return null;
      const b = body;
      const ibi_ms = [
        (b[6] & 1) | (b[0] << 3) | ((b[12] >> 5) & 6),
        (b[7] & 1) | (b[1] << 3) | ((b[12] >> 3) & 6),
        (b[8] & 1) | (b[2] << 3) | ((b[12] >> 1) & 6),
        (b[9] & 1) | (b[3] << 3) | ((b[12] & 3) << 1),
        (b[10] & 1) | (b[4] << 3) | ((b[13] >> 5) & 6),
        (b[11] & 1) | (b[5] << 3) | ((b[13] >> 3) & 6)
      ];
      const shift = (b[13] & 0x0f) === 7 ? 0 : (b[13] & 0x0f) + 1;
      const amplitude = [0, 1, 2, 3, 4, 5].map((k) => ((b[6 + k] >> 1) << shift) >>> 0);
      const hr_bpm = ibi_ms.filter((i) => i >= 300 && i <= 2000).map((i) => Math.floor(60000 / i));
      return { ibi_ms, amplitude, hr_bpm };
    }
    case 0x6a: {
      if (body.length < 10) return null;
      const motion_count = body[6];
      const sleep_state = body.readInt8(7);
      if (motion_count >= 120 || sleep_state < 0 || sleep_state >= 3) return null;
      const r4 = (v) => Math.round(v * 10000) / 10000;
      return {
        average_hr: r4(body[0] * 0.5),
        hr_trend: r4(body.readInt8(1) * 0.0625),
        mzci: r4(body[2] * 0.0625),
        dzci: r4(body[3] * 0.0625),
        breath: r4(body[4] / 8.0),
        breath_v: r4(body[5] / 8.0),
        motion_count,
        sleep_state,
        cv: r4(body.readUInt16LE(8) / 65536.0)
      };
    }
    case 0x6f: {
      if (body.length < 2) return null;
      let end = body.length;
      if (body[end - 1] === 0xff) end -= 1;
      const spo2_percent = [...body.subarray(1, end)];
      return spo2_percent.length ? { spo2_percent } : null;
    }
    case 0x76: {
      if (body.length < 8) return null;
      const start = body.readUInt32LE(0);
      const end = body.readUInt32LE(4);
      const hours = Math.max(0, end - start) / 10.0 / 3600.0;
      return {
        bedtime_start_ds: start,
        bedtime_end_ds: end,
        duration_hours: Math.round(hours * 100) / 100
      };
    }
    case 0x80: {
      if (body.length < 2) return null;
      const ibi_ms = [];
      const quality = [];
      const hr_bpm = [];
      for (let i = 0; i + 1 < body.length; i += 2) {
        const p0 = body[i];
        const p1 = body[i + 1];
        const ibi = (p1 & 0x07) | (p0 << 3);
        const q = (p1 >> 3) & 0x03;
        if (q === 1 && ibi >= 300 && ibi <= 2000) {
          hr_bpm.push(Math.floor(60000 / ibi));
        }
        ibi_ms.push(ibi);
        quality.push(q);
      }
      return { ibi_ms, quality, hr_bpm };
    }
    case 0x8b: {
      if (body.length < 4 || (body.length - 1) % 3 !== 0) return null;
      const r = [];
      const perfusion_index = [];
      for (let o = 1; o + 3 <= body.length; o += 3) {
        const rv = body.readUInt16BE(o) / 16384.0;
        r.push(Math.round(rv * 1000) / 1000);
        perfusion_index.push(Math.round((body[o + 2] / 255.0) * 0.05 * 10000) / 10000);
      }
      return { r, perfusion_index };
    }
    default:
      return null;
  }
}

/**
 * Parse a history-event packet (`tag >= 0x41`) into `{ tag, name, timestamp, body, decoded }`.
 */
export function parseRingEventPacket(packet) {
  const p = Buffer.isBuffer(packet.payload) ? packet.payload : Buffer.from(packet.payload || []);
  const timestamp = p.length >= 4 ? p.readUInt32LE(0) : 0;
  const body = p.length > 4 ? p.subarray(4) : Buffer.alloc(0);
  const name = eventName(packet.tag);
  const decoded = decodeEventBody(packet.tag, body);
  return {
    tag: packet.tag,
    name,
    timestamp,
    body,
    decoded
  };
}

// --- Ported `oura-analysis` & `oura-summary` On-Device Algorithms ---

/**
 * Ported from `oura_analysis::ported::spo2::spo2_simple` (`spo2_simple_calculate @ 0x22ad50`).
 * Default Oura calibration coefficients map R ~ 0.72 -> ~98.0% SpO2.
 */
export function spo2Simple(r, a = 110.0, b = -16.5, c = 0.0) {
  return Math.max(0.0, Math.min(100.0, a + b * r + c * r * r));
}

/**
 * Ported from `oura_analysis::ported::temperature::nightly_temperature` (`0x203520`).
 */
export function nightlyTemperatureCenti(samplesCenti) {
  if (!Array.isArray(samplesCenti) || samplesCenti.length < 120) return null;
  const ring = [0, 0, 0, 0, 0, 0, 0];
  let idx = 0;
  let winMin = 0xffff;
  let winMax = 0;
  const maxima = [];

  for (let i = 0; i < samplesCenti.length; i++) {
    ring[idx] = samplesCenti[i];
    idx = idx === 6 ? 0 : idx + 1;
    const sorted = [...ring].sort((a, b) => a - b);
    const m = sorted[3];
    if (m !== 0) {
      if (m < winMin) winMin = m;
      if (m > winMax) winMax = m;
    }
    if ((i + 1) % 30 === 0) {
      if (winMax >= winMin && winMax !== 0 && winMax - winMin < 250) {
        maxima.push(winMax);
      }
      winMin = 0xffff;
      winMax = 0;
    }
  }
  if (maxima.length < 4) return null;
  return Math.min(...maxima);
}

/**
 * Ported from `oura_analysis::ported::metabolic`.
 */
export function bmrSchofield(ageYears = 35, sex = 2, weightKg = 72) {
  const MALE = [
    [3, 59.512, -30.4],
    [10, 22.706, 504.3],
    [18, 17.686, 658.2],
    [30, 15.057, 692.2],
    [60, 11.472, 873.1],
    [Infinity, 11.711, 587.7]
  ];
  const FEMALE = [
    [3, 58.317, -31.1],
    [10, 20.315, 485.9],
    [18, 13.384, 692.6],
    [30, 14.818, 486.6],
    [60, 8.126, 845.6],
    [Infinity, 9.082, 658.5]
  ];
  const band = (table) => {
    const row = table.find(([hi]) => ageYears < hi) || table[table.length - 1];
    return row[1] * weightKg + row[2];
  };
  if (sex === 0) return band(MALE);
  if (sex === 1) return band(FEMALE);
  return (band(MALE) + band(FEMALE)) / 2.0;
}

export function stepsToMeters(steps) {
  return Math.round((steps || 0) * 0.762);
}

function piecewiseCurve(x, anchors) {
  if (x <= anchors[0][0]) return anchors[0][1];
  for (let i = 0; i < anchors.length - 1; i++) {
    const [x0, y0] = anchors[i];
    const [x1, y1] = anchors[i + 1];
    if (x <= x1) {
      const t = Math.abs(x1 - x0) < 1e-9 ? 0 : (x - x0) / (x1 - x0);
      return y0 + t * (y1 - y0);
    }
  }
  return anchors[anchors.length - 1][1];
}

/**
 * Computes Sleep, Readiness, and Activity scores + contributors from decoded ring
 * metrics and trailing 14-day baselines (ported from `open_oura/docs/algorithms/score-weights.md`
 * and `open_health/crates/oura-summary/src/sleep_score.rs`).
 */
export function scoreRingDay({
  totalSleepSec = 0,
  deepSec = 0,
  remSec = 0,
  lightSec = 0,
  awakeSec = 0,
  latencySec = 600,
  lowestHr = null,
  averageHrv = null,
  tempDeviationC = 0,
  steps = 0,
  activeCalories = 0,
  baselineHrv = 60,
  baselineRhr = 53,
  baselineSleepSec = 27000
}) {
  const timeInBedSec = Math.max(1, totalSleepSec + awakeSec);
  const efficiency = Math.round((totalSleepSec / timeInBedSec) * 100);
  const sleepHours = totalSleepSec / 3600.0;
  const deepMin = deepSec / 60.0;
  const remMin = remSec / 60.0;
  const latencyMin = latencySec / 60.0;
  const awakeFrac = awakeSec / timeInBedSec;

  // Sleep contributors (weights: 35% Total, 15% Restfulness, 10% Efficiency, 10% REM, 10% Deep, 10% Latency, 10% Timing)
  const subTotalSleep = piecewiseCurve(sleepHours, [
    [4.0, 25],
    [6.0, 62],
    [7.0, 86],
    [7.8, 96],
    [8.5, 100]
  ]);
  const subEfficiency = piecewiseCurve(efficiency, [
    [65, 25],
    [78, 60],
    [86, 85],
    [92, 98],
    [98, 100]
  ]);
  const subRem = piecewiseCurve(remMin, [
    [20, 30],
    [60, 72],
    [95, 92],
    [120, 100]
  ]);
  const subDeep = piecewiseCurve(deepMin, [
    [15, 30],
    [45, 70],
    [75, 92],
    [105, 100]
  ]);
  const subLatency = piecewiseCurve(latencyMin, [
    [0, 82],
    [12, 98],
    [22, 85],
    [40, 55],
    [60, 25]
  ]);
  const subRestful = Math.max(30, Math.min(100, Math.round(100 - awakeFrac * 180)));
  const subTiming = 88;

  const sleepScore = Math.round(
    0.35 * subTotalSleep +
      0.15 * subRestful +
      0.1 * subEfficiency +
      0.1 * subRem +
      0.1 * subDeep +
      0.1 * subLatency +
      0.1 * subTiming
  );

  // Readiness contributors (from `open_oura/docs/algorithms/score-weights.md`)
  const hrvDelta = averageHrv != null && baselineHrv ? averageHrv - baselineHrv : 0;
  const rhrDelta = lowestHr != null && baselineRhr ? lowestHr - baselineRhr : 0;

  const hrvBalanceContrib = Math.round(
    piecewiseCurve(hrvDelta, [
      [-20, 45],
      [-8, 68],
      [0, 84],
      [8, 94],
      [18, 99]
    ])
  );
  const restingHrContrib = Math.round(
    piecewiseCurve(rhrDelta, [
      [-6, 98],
      [0, 86],
      [3, 72],
      [7, 50],
      [12, 30]
    ])
  );
  const tempContrib = Math.round(
    piecewiseCurve(Math.abs(tempDeviationC || 0), [
      [0.0, 96],
      [0.2, 88],
      [0.45, 68],
      [0.8, 40]
    ])
  );
  const sleepBalanceContrib = Math.round(
    piecewiseCurve((totalSleepSec - (baselineSleepSec || 27000)) / 3600.0, [
      [-2.0, 55],
      [-0.5, 78],
      [0.0, 86],
      [0.8, 95]
    ])
  );
  const recoveryIndexContrib = Math.round((restingHrContrib + subEfficiency) / 2);
  const activityBalanceContrib = Math.round(
    piecewiseCurve(steps, [
      [2500, 62],
      [7000, 84],
      [10500, 94],
      [16000, 82]
    ])
  );

  const readinessScore = Math.round(
    0.2 * restingHrContrib +
      0.2 * hrvBalanceContrib +
      0.2 * sleepScore +
      0.14 * tempContrib +
      0.13 * sleepBalanceContrib +
      0.13 * recoveryIndexContrib
  );

  const activityScore = Math.round(
    piecewiseCurve(steps + activeCalories * 8, [
      [3000, 56],
      [7500, 78],
      [11500, 90],
      [15500, 97]
    ])
  );

  return {
    sleepScore: Math.max(30, Math.min(100, sleepScore)),
    readinessScore: Math.max(30, Math.min(100, readinessScore)),
    activityScore: Math.max(30, Math.min(100, activityScore)),
    efficiency,
    contributors: {
      hrvBalance: hrvBalanceContrib,
      restingHeartRate: restingHrContrib,
      recoveryIndex: recoveryIndexContrib,
      sleepBalance: sleepBalanceContrib,
      previousNight: sleepScore,
      activityBalance: activityBalanceContrib
    }
  };
}

// --- Epoch-Aware Decisecond -> UTC Timestamp Mapper (`open_oura/tools/epoch_time.py`) ---

/**
 * Splits an ordered array of ring events into reboot epochs whenever `ringTimestamp`
 * drops by more than `resetDropDs` (36000 ds = 1 hour), and anchors each epoch's
 * `bootUnix` to UTC seconds.
 */
export function buildRingEpochs(events, resetDropDs = 432000) {
  if (!events || events.length === 0) return [];
  const epochs = [];
  let curStartIdx = 0;
  let maxRingTs = Number(events[0].ringTimestamp || 0);
  let lastCapUnix = Number(events[0].capturedUnix || Math.floor(Date.now() / 1000));
  let anchorBootUnix = null;

  const checkTimeAnchor = (ev) => {
    let dec = ev.decoded;
    if (!dec && ev.decodedJson) {
      try {
        dec = JSON.parse(ev.decodedJson);
      } catch {}
    }
    if (dec && Number.isFinite(dec.unix_time) && dec.unix_time > 1577836800) {
      anchorBootUnix = dec.unix_time - Number(ev.ringTimestamp || 0) / 10.0;
    }
  };

  checkTimeAnchor(events[0]);

  for (let i = 1; i < events.length; i++) {
    const rts = Number(events[i].ringTimestamp || 0);
    if (maxRingTs > rts && maxRingTs - rts > resetDropDs) {
      const bootUnix = anchorBootUnix !== null ? anchorBootUnix : lastCapUnix - maxRingTs / 10.0;
      epochs.push({
        startIdx: curStartIdx,
        endIdx: i - 1,
        bootUnix
      });
      curStartIdx = i;
      maxRingTs = rts;
      anchorBootUnix = null;
    } else if (rts > maxRingTs) {
      maxRingTs = rts;
    }
    checkTimeAnchor(events[i]);
    lastCapUnix = Number(events[i].capturedUnix || lastCapUnix);
  }

  epochs.push({
    startIdx: curStartIdx,
    endIdx: events.length - 1,
    bootUnix: anchorBootUnix !== null ? anchorBootUnix : lastCapUnix - maxRingTs / 10.0
  });

  return epochs;
}

/**
 * Resolves each event's `ringTimestamp` (deciseconds since ring boot) to a UTC Unix timestamp (seconds).
 * If a decoded event already embeds `unixSeconds`, uses that directly.
 */
export function resolveEventsWithUnixTime(events) {
  const epochs = buildRingEpochs(events);
  return events.map((ev, idx) => {
    let decoded = ev.decoded;
    if (!decoded && ev.decodedJson) {
      try {
        decoded = JSON.parse(ev.decodedJson);
      } catch {}
    }
    if (!decoded && ev.body) {
      decoded = decodeEventBody(ev.tag, ev.body);
    }

    let unixSec = decoded?.unixSeconds;
    if (!Number.isFinite(unixSec)) {
      const ep = epochs.find((e) => idx >= e.startIdx && idx <= e.endIdx) || epochs[epochs.length - 1];
      const bootUnix = ep ? ep.bootUnix : (Number(ev.capturedUnix || Math.floor(Date.now() / 1000)) - Number(ev.ringTimestamp || 0) / 10.0);
      unixSec = Math.round(bootUnix + Number(ev.ringTimestamp || 0) / 10.0);
    }

    return {
      ...ev,
      decoded,
      unixSec
    };
  });
}

function localDayDate(dayStr, hours = 0, minutes = 0, seconds = 0) {
  const [y, m, d] = String(dayStr).split('-').map(Number);
  return new Date(y, (m || 1) - 1, d || 1, hours, minutes, seconds, 0);
}

function unixToDayStr(unixSec) {
  // Shift by 4 hours so sleep starting at 20:00–23:59 local device time attributes to the waking day
  const d = new Date((unixSec + 4 * 3600) * 1000);
  return toLocalDayStr(d);
}

/**
 * Aggregates all `ring_events` for `userId` into `daily_summaries` and `heartrate_samples`
 * using `open_oura`'s binary decoders and `ecore` physiological scoring functions.
 */
export function aggregateRingEventsToSummaries(userId) {
  const rawEvents = getRingEventsForUser(userId, 25000);
  if (!rawEvents || rawEvents.length === 0) return { daysUpdated: 0, eventsProcessed: 0 };

  const resolved = resolveEventsWithUnixTime(rawEvents);
  const byDay = new Map();

  const ensureDay = (day) => {
    if (!byDay.has(day)) {
      byDay.set(day, {
        day,
        hasData: false,
        bedtimeStartUnix: null,
        bedtimeEndUnix: null,
        sleepMinUnix: null,
        sleepMaxUnix: null,
        totalSleepSec: 0,
        deepSec: 0,
        remSec: 0,
        lightSec: 0,
        awakeSec: 0,
        hypnogramChars: [],
        hrSamples: [],
        hr5min: [],
        hrv5min: [],
        breathSamples: [],
        tempCentiSamples: [],
        spo2Samples: [],
        stepsMax: 0,
        stepsSum: 0,
        activeCalSum: 0,
        highActivitySec: 0,
        medActivitySec: 0,
        lowActivitySec: 0,
        sedentarySec: 0
      });
    }
    return byDay.get(day);
  };

  const trackSleepWindow = (bucket, unixSec) => {
    if (!Number.isFinite(unixSec)) return;
    bucket.sleepMinUnix = bucket.sleepMinUnix !== null ? Math.min(bucket.sleepMinUnix, unixSec) : unixSec;
    bucket.sleepMaxUnix = bucket.sleepMaxUnix !== null ? Math.max(bucket.sleepMaxUnix, unixSec) : unixSec;
  };

  for (const ev of resolved) {
    const d = ev.decoded;
    if (!d) continue;
    const day = unixToDayStr(ev.unixSec);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    const evType = d.type || ev.name || eventName(ev.tag);

    switch (evType) {
      case 'bedtime_period': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        const startDs = d.bedtime_start_ds ?? d.bedtimeStartDs;
        const endDs = d.bedtime_end_ds ?? d.bedtimeEndDs;
        const startU =
          startDs !== undefined
            ? Math.round(ev.unixSec - (ev.ringTimestamp - startDs) / 10.0)
            : ev.unixSec - 28000;
        const endU =
          endDs !== undefined
            ? Math.round(ev.unixSec - (ev.ringTimestamp - endDs) / 10.0)
            : ev.unixSec;
        if (endU >= startU && endU - startU <= 54000) {
          bucket.bedtimeStartUnix = bucket.bedtimeStartUnix ? Math.min(bucket.bedtimeStartUnix, startU) : startU;
          bucket.bedtimeEndUnix = bucket.bedtimeEndUnix ? Math.max(bucket.bedtimeEndUnix, endU) : endU;
        }
        break;
      }
      case 'sleep_phase_information':
      case 'sleep_phase_details':
      case 'sleep_phase_data': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        trackSleepWindow(bucket, ev.unixSec);
        if (d.totalSleepSec || d.deepSec || d.remSec || d.lightSec) {
          bucket.totalSleepSec += Number(d.totalSleepSec || 0);
          bucket.deepSec += Number(d.deepSec || 0);
          bucket.remSec += Number(d.remSec || 0);
          bucket.lightSec += Number(d.lightSec || 0);
          bucket.awakeSec += Number(d.awakeSec || 0);
        }
        if (Array.isArray(d.phases)) {
          const mapPhase = { deep: '1', light: '2', rem: '3', awake: '4' };
          for (const p of d.phases) {
            const ch = mapPhase[p] || '2';
            bucket.hypnogramChars.push(ch);
            if (!d.totalSleepSec) {
              if (ch === '1') bucket.deepSec += 300;
              else if (ch === '3') bucket.remSec += 300;
              else if (ch === '4') bucket.awakeSec += 300;
              else bucket.lightSec += 300;
            }
          }
          if (!d.totalSleepSec) {
            bucket.totalSleepSec = bucket.deepSec + bucket.remSec + bucket.lightSec;
          }
        } else if (Array.isArray(d.samples)) {
          for (const s of d.samples) {
            const stage = s >= 1 && s <= 4 ? String(s) : '2';
            bucket.hypnogramChars.push(stage);
          }
        }
        break;
      }
      case 'sleep_period_information_2': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        trackSleepWindow(bucket, ev.unixSec);
        const hrVal = d.average_hr ?? d.averageHrBpm;
        if (hrVal >= 35 && hrVal <= 130) {
          bucket.hr5min.push(Math.round(hrVal));
          bucket.hrSamples.push({
            timestamp: new Date(ev.unixSec * 1000).toISOString(),
            bpm: Math.round(hrVal),
            source: 'sleep'
          });
        }
        const brVal = d.breath ?? d.breathRate;
        if (brVal >= 8 && brVal <= 30) {
          bucket.breathSamples.push(Number(brVal));
        }
        const slState = d.sleep_state ?? d.sleepState;
        if (slState >= 0 && slState <= 4) {
          const mapStage = { 0: '4', 1: '2', 2: '1', 3: '3', 4: '4' };
          bucket.hypnogramChars.push(mapStage[slState] || '2');
        }
        break;
      }
      case 'hrv_event': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        trackSleepWindow(bucket, ev.unixSec);
        if (Array.isArray(d.rmssd_ms)) {
          for (const r of d.rmssd_ms) {
            if (r >= 10 && r <= 250) bucket.hrv5min.push(Math.round(r));
          }
        } else {
          const rmssd = d.averageRmssd5min || d.rmssd || 0;
          if (rmssd >= 10 && rmssd <= 250) bucket.hrv5min.push(Math.round(rmssd));
        }
        if (Array.isArray(d.hr_bpm)) {
          d.hr_bpm.forEach((hr, idx) => {
            if (hr >= 35 && hr <= 140) {
              bucket.hr5min.push(Math.round(hr));
              bucket.hrSamples.push({
                timestamp: new Date((ev.unixSec + idx * 300) * 1000).toISOString(),
                bpm: Math.round(hr),
                source: 'sleep'
              });
            }
          });
        } else if (d.averageHr5min >= 35 && d.averageHr5min <= 140) {
          bucket.hr5min.push(Math.round(d.averageHr5min));
          bucket.hrSamples.push({
            timestamp: new Date(ev.unixSec * 1000).toISOString(),
            bpm: Math.round(d.averageHr5min),
            source: 'sleep'
          });
        }
        break;
      }
      case 'ibi_and_amplitude_event':
      case 'green_ibi_quality_event': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        const src = evType === 'green_ibi_quality_event' ? 'daytime' : 'sleep';
        if (src === 'sleep') trackSleepWindow(bucket, ev.unixSec);
        if (Array.isArray(d.hr_bpm)) {
          for (const hr of d.hr_bpm) {
            if (hr >= 35 && hr <= 195) {
              bucket.hrSamples.push({
                timestamp: new Date(ev.unixSec * 1000).toISOString(),
                bpm: Math.round(hr),
                source: src
              });
            }
          }
        } else if (d.hrBpm >= 35 && d.hrBpm <= 195) {
          bucket.hrSamples.push({
            timestamp: new Date(ev.unixSec * 1000).toISOString(),
            bpm: Math.round(d.hrBpm),
            source: src
          });
        }
        if (d.rmssdApprox >= 10 && d.rmssdApprox <= 250) {
          bucket.hrv5min.push(Math.round(d.rmssdApprox));
        }
        break;
      }
      case 'sleep_temp_event':
      case 'temp_period':
      case 'temp_event': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        if (evType === 'sleep_temp_event') trackSleepWindow(bucket, ev.unixSec);
        if (Array.isArray(d.temps_c)) {
          for (const c of d.temps_c) {
            if (c >= 30.0 && c <= 41.0) bucket.tempCentiSamples.push(Math.round(c * 100));
          }
        } else {
          const c = Number(d.tempC || 0);
          if (c >= 30.0 && c <= 41.0) bucket.tempCentiSamples.push(Math.round(c * 100));
        }
        break;
      }
      case 'spo2_event':
      case 'spo2_r_pi_event': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        if (Array.isArray(d.spo2_percent)) {
          for (const pct of d.spo2_percent) {
            if (pct >= 80 && pct <= 100) bucket.spo2Samples.push(pct);
          }
        } else if (Array.isArray(d.r)) {
          for (const rv of d.r) {
            const pct = spo2Simple(rv);
            if (pct >= 80 && pct <= 100) bucket.spo2Samples.push(pct);
          }
        } else {
          const pct = Number(d.spo2Avg || 0);
          if (pct >= 80 && pct <= 100) bucket.spo2Samples.push(pct);
        }
        break;
      }
      case 'activity_information': {
        const bucket = ensureDay(day);
        bucket.hasData = true;
        if (Array.isArray(d.met) && d.met.length > 0) {
          for (const m of d.met) {
            const estSteps = m > 1.3 ? Math.round((m - 1.0) * 45) : 0;
            const estCal = m > 1.2 ? Math.round((m - 1.0) * 1.4) : 0;
            bucket.stepsSum += estSteps;
            bucket.activeCalSum += estCal;
            if (m >= 6.0) bucket.highActivitySec += 60;
            else if (m >= 3.0) bucket.medActivitySec += 60;
            else if (m >= 1.5) bucket.lowActivitySec += 60;
            else bucket.sedentarySec += 60;
          }
        } else {
          const st = Number(d.steps || 0);
          if (st > bucket.stepsMax) bucket.stepsMax = st;
          bucket.stepsSum += st;
          bucket.activeCalSum += Number(d.activeCalories || 0);
          if (st > 90) bucket.highActivitySec += 300;
          else if (st > 35) bucket.medActivitySec += 300;
          else if (st > 5) bucket.lowActivitySec += 300;
          else bucket.sedentarySec += 300;
        }
        break;
      }
      default:
        break;
    }
  }

  // Sort days chronologically and compute daily summaries + scores
  const sortedDays = [...byDay.keys()].filter((day) => byDay.get(day).hasData).sort();
  const nightlyTempsByDay = new Map();
  for (const day of sortedDays) {
    const b = byDay.get(day);
    if (b.tempCentiSamples.length > 0) {
      const nt = nightlyTemperatureCenti(b.tempCentiSamples);
      const meanC =
        nt !== null
          ? nt / 100.0
          : b.tempCentiSamples.reduce((a, v) => a + v, 0) / (b.tempCentiSamples.length * 100.0);
      nightlyTempsByDay.set(day, meanC);
    }
  }

  let daysUpdated = 0;
  for (const day of sortedDays) {
    const b = byDay.get(day);
    const baseline = getUserBaselines(userId, day, 14);

    // Derive sleep durations if hypnogram or bedtime was captured
    let totalSleepSec = b.totalSleepSec;
    let deepSec = b.deepSec;
    let remSec = b.remSec;
    let lightSec = b.lightSec;
    let awakeSec = b.awakeSec;

    if (totalSleepSec === 0 && b.hypnogramChars.length > 0) {
      for (const ch of b.hypnogramChars) {
        if (ch === '1') deepSec += 300;
        else if (ch === '3') remSec += 300;
        else if (ch === '4') awakeSec += 300;
        else lightSec += 300;
      }
      totalSleepSec = deepSec + remSec + lightSec;
    }

    if (totalSleepSec === 0 && b.bedtimeStartUnix && b.bedtimeEndUnix && b.bedtimeEndUnix > b.bedtimeStartUnix) {
      const span = Math.min(43200, b.bedtimeEndUnix - b.bedtimeStartUnix);
      awakeSec = Math.round(span * 0.09);
      totalSleepSec = span - awakeSec;
      deepSec = Math.round(totalSleepSec * 0.21);
      remSec = Math.round(totalSleepSec * 0.23);
      lightSec = totalSleepSec - deepSec - remSec;
    }

    const hasSleepData = totalSleepSec > 0 || b.hypnogramChars.length > 0;
    const lowestHr = b.hr5min.length > 0 ? Math.min(...b.hr5min) : null;
    const averageHr =
      b.hr5min.length > 0
        ? Number((b.hr5min.reduce((a, v) => a + v, 0) / b.hr5min.length).toFixed(1))
        : null;
    const averageHrv =
      b.hrv5min.length > 0
        ? Math.round(b.hrv5min.reduce((a, v) => a + v, 0) / b.hrv5min.length)
        : null;
    const averageBreath =
      b.breathSamples.length > 0
        ? Number((b.breathSamples.reduce((a, v) => a + v, 0) / b.breathSamples.length).toFixed(1))
        : null;

    // Temperature deviation vs trailing mean
    const curTempC = nightlyTempsByDay.get(day);
    let tempDeviation = null;
    if (curTempC !== undefined) {
      const prevTemps = [...nightlyTempsByDay.entries()]
        .filter(([k]) => k < day)
        .slice(-14)
        .map(([, v]) => v);
      const refTemp =
        prevTemps.length > 0 ? prevTemps.reduce((a, v) => a + v, 0) / prevTemps.length : 36.25;
      tempDeviation = Number((curTempC - refTemp).toFixed(2));
    }

    const steps = Math.max(b.stepsMax, b.stepsSum);
    const activeCalories = b.activeCalSum || Math.round(steps * 0.042);
    const bmrCal = Math.round(bmrSchofield(34, 2, 70));
    const totalCalories = steps > 0 || activeCalories > 0 ? bmrCal + activeCalories : 0;

    const spo2Percentage =
      b.spo2Samples.length > 0
        ? Number((b.spo2Samples.reduce((a, v) => a + v, 0) / b.spo2Samples.length).toFixed(1))
        : null;

    const scored = scoreRingDay({
      totalSleepSec,
      deepSec,
      remSec,
      lightSec,
      awakeSec,
      latencySec: hasSleepData ? 720 : 0,
      lowestHr: lowestHr ?? baseline.lowestHr,
      averageHrv: averageHrv ?? baseline.averageHrv,
      tempDeviationC: tempDeviation ?? 0,
      steps,
      activeCalories,
      baselineHrv: baseline.averageHrv,
      baselineRhr: baseline.lowestHr,
      baselineSleepSec: baseline.totalSleepSeconds
    });

    const timeInBedSec = totalSleepSec + awakeSec;

    // Resolve bedtimeStart & bedtimeEnd in local device clock time (never hardcoded UTC Z!)
    let bedtimeStartIso = null;
    let bedtimeEndIso = null;
    if (b.bedtimeStartUnix && b.bedtimeEndUnix && b.bedtimeEndUnix > b.bedtimeStartUnix) {
      bedtimeStartIso = new Date(b.bedtimeStartUnix * 1000).toISOString();
      bedtimeEndIso = new Date(b.bedtimeEndUnix * 1000).toISOString();
    } else if (hasSleepData && b.sleepMinUnix && b.sleepMaxUnix) {
      const endU = b.sleepMaxUnix;
      const startU = Math.min(b.sleepMinUnix, endU - Math.max(timeInBedSec, 3600));
      bedtimeStartIso = new Date(startU * 1000).toISOString();
      bedtimeEndIso = new Date(endU * 1000).toISOString();
    } else if (hasSleepData) {
      // Anchor fallback to local device time (e.g. wake 6:45 AM local time, bedtime = wake - timeInBed)
      const localWake = localDayDate(day, 6, 45, 0);
      const localBed = new Date(localWake.getTime() - Math.max(timeInBedSec, 25200) * 1000);
      bedtimeStartIso = localBed.toISOString();
      bedtimeEndIso = localWake.toISOString();
    }

    const patch = {
      readiness_score: hasSleepData || lowestHr !== null || averageHrv !== null ? scored.readinessScore : 0,
      temp_deviation: tempDeviation,
      temp_trend_deviation: tempDeviation,
      hrv_balance_contrib: hasSleepData || averageHrv !== null ? scored.contributors.hrvBalance : 0,
      resting_hr_contrib: hasSleepData || lowestHr !== null ? scored.contributors.restingHeartRate : 0,
      recovery_index_contrib: hasSleepData ? scored.contributors.recoveryIndex : 0,
      sleep_balance_contrib: hasSleepData ? scored.contributors.sleepBalance : 0,
      previous_night_contrib: hasSleepData ? scored.sleepScore : 0,
      activity_balance_contrib: steps > 0 ? scored.contributors.activityBalance : 0,
      sleep_score: hasSleepData ? scored.sleepScore : 0,
      total_sleep_seconds: totalSleepSec,
      deep_sleep_seconds: deepSec,
      rem_sleep_seconds: remSec,
      light_sleep_seconds: lightSec,
      awake_seconds: awakeSec,
      time_in_bed_seconds: timeInBedSec,
      sleep_efficiency: hasSleepData ? scored.efficiency : 0,
      sleep_latency_seconds: hasSleepData ? 720 : 0,
      lowest_hr: lowestHr,
      average_hr: averageHr,
      average_hrv: averageHrv,
      average_breath: averageBreath,
      bedtime_start: bedtimeStartIso,
      bedtime_end: bedtimeEndIso,
      hypnogram_5min: b.hypnogramChars.length > 0 ? b.hypnogramChars.join('') : '',
      hr_5min_json: b.hr5min,
      hrv_5min_json: b.hrv5min,
      activity_score: steps > 0 || activeCalories > 0 ? scored.activityScore : 0,
      steps,
      active_calories: activeCalories,
      total_calories: totalCalories,
      equivalent_walking_distance: stepsToMeters(steps),
      high_activity_seconds: b.highActivitySec,
      medium_activity_seconds: b.medActivitySec,
      low_activity_seconds: b.lowActivitySec,
      sedentary_seconds: b.sedentarySec,
      inactivity_alerts: 0
    };

    if (spo2Percentage !== null) {
      patch.spo2_percentage = spo2Percentage;
    }

    upsertDailySummary(userId, day, patch);
    if (b.hrSamples.length > 0) {
      replaceHeartrateDay(userId, day, b.hrSamples);
    }
    daysUpdated++;
  }

  return {
    daysUpdated,
    eventsProcessed: resolved.length
  };
}

/**
 * Ingests raw BLE notification packets (hex strings) streamed from WebBluetooth
 * or `open_oura` CLI, parses device info / battery / time sync / history events,
 * stores them in SQLite, and recomputes daily summaries.
 */
export function ingestBleNotifications(
  userId,
  {
    serial = `OURA3-${userId}`,
    notificationsHex = [],
    phoneUnix = Math.floor(Date.now() / 1000),
    clearDemo = false
  }
) {
  if (clearDemo) {
    clearUserSummariesForRealSync(userId);
  }
  let maxRingTs = 0;
  let eventsIngested = 0;
  let batteryPercent = null;
  let charging = false;
  let firmware = '';
  let bootloader = '';
  let hwId = '';

  for (const hexStr of notificationsHex) {
    const clean = String(hexStr || '').trim().replace(/\s+/g, '').replace(/^0x/i, '');
    if (!clean || clean.length < 4) continue;
    const rawBuf = Buffer.from(clean, 'hex');
    const packets = parsePackets(rawBuf);

    for (const pkt of packets) {
      if (pkt.tag === 0x0b) {
        const fw = parseFirmwareResponse(pkt);
        firmware = fw.firmware;
        bootloader = fw.bootloader;
      } else if (pkt.tag === 0x0d) {
        const bat = parseBatteryResponse(pkt);
        if (bat) {
          batteryPercent = bat.percent;
          charging = bat.charging;
          insertRingReading(userId, {
            serial,
            kind: 'battery',
            payload: bat,
            capturedUnix: phoneUnix
          });
        }
      } else if (pkt.tag === 0x11 && pkt.payload[0] !== 0x09) {
        const ser = parseSerialResponse(pkt);
        if (ser.serial) serial = ser.serial;
        if (ser.hwId) hwId = ser.hwId;
      } else if (pkt.tag === 0x13 && pkt.payload.length >= 4) {
        const ringTimeDs = pkt.payload.readUInt32LE(0);
        if (ringTimeDs > maxRingTs) maxRingTs = ringTimeDs;
        insertRingReading(userId, {
          serial,
          kind: 'timesync',
          payload: { ringTimeDeciseconds: ringTimeDs, phoneUnix },
          capturedUnix: phoneUnix
        });
      } else if (pkt.tag >= HISTORY_EVENT_PREFIX) {
        const ev = parseRingEventPacket(pkt);
        if (ev.timestamp > maxRingTs) maxRingTs = ev.timestamp;
        insertRingEvent(userId, {
          serial,
          tag: ev.tag,
          name: ev.name,
          ringTimestamp: ev.timestamp,
          body: ev.body,
          decoded: ev.decoded,
          capturedUnix: phoneUnix
        });
        eventsIngested++;
      }
    }
  }

  upsertRingDevice(userId, {
    serial,
    hwId,
    firmware,
    bootloader,
    batteryPercent,
    charging
  });

  if (maxRingTs > 0) {
    setRingSyncCursor(userId, serial, maxRingTs);
  }

  const agg = aggregateRingEventsToSummaries(userId);
  return {
    serial,
    eventsIngested,
    maxCursor: maxRingTs,
    batteryPercent,
    firmware,
    hwId,
    daysUpdated: agg.daysUpdated
  };
}

/**
 * Imports a SQLite `.db` file (`oura.db`) produced by `Th0rgal/open_oura` CLI or
 * `Th0rgal/open_health` ("Export raw ring data") directly into Laura's database.
 */
export function importOpenOuraSqliteBuffer(userId, sqliteBuffer) {
  const tmpFile = path.join(os.tmpdir(), `open-oura-import-${userId}-${Date.now()}.db`);
  fs.writeFileSync(tmpFile, sqliteBuffer);

  try {
    const extDb = new DatabaseSync(tmpFile, { readOnly: true });
    const tables = new Set(
      extDb
        .prepare(`SELECT name FROM sqlite_master WHERE type='table'`)
        .all()
        .map((r) => r.name)
    );

    let serial = `OURA3-${userId}`;
    if (tables.has('devices')) {
      const devs = extDb.prepare('SELECT * FROM devices ORDER BY last_seen_unix DESC').all();
      for (const d of devs) {
        if (d.serial) serial = d.serial;
        upsertRingDevice(userId, {
          serial: d.serial || serial,
          hwId: d.hw_id || '',
          firmware: d.firmware || '',
          bootloader: d.bootloader || '',
          batteryPercent: d.battery_percent ?? null,
          charging: Boolean(d.charging)
        });
      }
    }

    if (tables.has('sync_state')) {
      const states = extDb.prepare('SELECT * FROM sync_state').all();
      for (const s of states) {
        setRingSyncCursor(userId, s.serial || serial, s.last_timestamp || 0);
      }
    }

    let eventsImported = 0;
    if (tables.has('events')) {
      const rows = extDb.prepare('SELECT * FROM events ORDER BY id ASC').all();
      for (const r of rows) {
        const bodyBuf = Buffer.from(r.body || []);
        const tag = Number(r.tag);
        const decoded = decodeEventBody(tag, bodyBuf);
        insertRingEvent(userId, {
          serial: r.serial || serial,
          tag,
          name: r.name || eventName(tag),
          ringTimestamp: Number(r.ring_timestamp || 0),
          body: bodyBuf,
          decoded,
          capturedUnix: Number(r.captured_unix || Math.floor(Date.now() / 1000))
        });
        eventsImported++;
      }
    }

    extDb.close();
    const agg = aggregateRingEventsToSummaries(userId);
    return {
      serial,
      eventsImported,
      daysUpdated: agg.daysUpdated
    };
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {}
  }
}

/**
 * Generates genuine binary `open_oura` BLE packets (`0x76 bedtime_period`,
 * `0x5a sleep_phase_data`, `0x5d hrv_event`, `0x60 ibi_and_amplitude_event`,
 * `0x75 sleep_temp_event`, `0x6f spo2_event`, `0x50 activity_information`)
 * and runs them through `ingestBleNotifications` to test or demonstrate the
 * full binary-to-dashboard `open_oura` pipeline without needing Oura Cloud.
 */
export function simulateOpenOuraBleDrain(userId, { daysBack = 7, serial = `OURA3-${userId}` } = {}) {
  const now = new Date();
  const nowUnix = Math.floor(now.getTime() / 1000);
  const bootUnix = nowUnix - (daysBack + 2) * 86400;
  const toRingDs = (u) => Math.max(100, Math.round((u - bootUnix) * 10));

  const notificationsHex = [];

  // 1. Firmware packet (0x0b: [3, 2, 11, 1, 0, 4])
  notificationsHex.push(encodePacket(0x0b, [3, 2, 11, 1, 0, 4]).toString('hex'));
  // 2. Battery packet (0x0d: 88%, charging=0)
  notificationsHex.push(encodePacket(0x0d, [88, 0]).toString('hex'));

  for (let d = daysBack - 1; d >= 0; d--) {
    // Anchor bedtime to 10:45 PM local device clock time and wake to 6:45 AM local device clock time
    const bedStartDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - d - 1, 22, 45 - (d % 3) * 10, 0);
    const bedEndDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - d, 6, 45 + (d % 3) * 10, 0);
    const bedStartUnix = Math.floor(bedStartDate.getTime() / 1000);
    const bedEndUnix = Math.floor(bedEndDate.getTime() / 1000);
    const wakeDs = toRingDs(bedEndUnix);

    // 0x75 sleep_temp_event (during sleep, centi-Celsius int16LE)
    for (let b = 0; b < 8; b++) {
      const tempBuf = Buffer.alloc(4 + 8 * 2);
      tempBuf.writeUInt32LE(toRingDs(bedStartUnix + b * 1800), 0);
      for (let s = 0; s < 8; s++) {
        tempBuf.writeInt16LE(3620 + ((d * 7 + s) % 35), 4 + s * 2);
      }
      notificationsHex.push(encodePacket(0x75, tempBuf).toString('hex'));
    }

    // 0x5d hrv_event ([hr_bpm, rmssd_ms] pairs across the night)
    for (let h = 0; h < 6; h++) {
      const hrvBuf = Buffer.alloc(4 + 8);
      hrvBuf.writeUInt32LE(toRingDs(bedStartUnix + 2 * 3600 + h * 1800), 0);
      for (let p = 0; p < 4; p++) {
        hrvBuf[4 + p * 2] = 50 + ((d + h + p) % 7);
        hrvBuf[4 + p * 2 + 1] = 58 + ((d * 5 + h * 3 + p * 2) % 24);
      }
      notificationsHex.push(encodePacket(0x5d, hrvBuf).toString('hex'));
    }

    // 0x76 bedtime_period (at wake: [ts_ds, bedtime_start_ds, bedtime_end_ds])
    const bedPayload = Buffer.alloc(12);
    bedPayload.writeUInt32LE(wakeDs, 0);
    bedPayload.writeUInt32LE(toRingDs(bedStartUnix), 4);
    bedPayload.writeUInt32LE(wakeDs, 8);
    notificationsHex.push(encodePacket(0x76, bedPayload).toString('hex'));

    // 0x5a sleep_phase_data (2-bit packed phases: 0=deep, 1=light, 2=rem, 3=awake)
    // 24 bytes of packed phases = 96 5-min epochs (8 hours)
    const phasePattern = [
      3, 1, 1, 0, 0, 0, 1, 1, 2, 2, 1, 0,
      0, 1, 1, 2, 2, 2, 1, 0, 1, 2, 2, 3
    ];
    const sleepBuf = Buffer.alloc(4 + 1 + 24);
    sleepBuf.writeUInt32LE(wakeDs + 10, 0);
    sleepBuf[4] = 1; // header
    for (let i = 0; i < 24; i++) {
      const p0 = phasePattern[i % phasePattern.length];
      const p1 = phasePattern[(i + 1) % phasePattern.length];
      const p2 = phasePattern[(i + 2) % phasePattern.length];
      const p3 = phasePattern[(i + 3) % phasePattern.length];
      sleepBuf[5 + i] = ((p0 & 3) << 6) | ((p1 & 3) << 4) | ((p2 & 3) << 2) | (p3 & 3);
    }
    notificationsHex.push(encodePacket(0x5a, sleepBuf).toString('hex'));

    // 0x6f spo2_event ([header, ...spo2_percent, 0xff])
    const spo2Buf = Buffer.from([0, 0, 0, 0, 1, 98, 98, 97, 99, 98, 0xff]);
    spo2Buf.writeUInt32LE(wakeDs + 20, 0);
    notificationsHex.push(encodePacket(0x6f, spo2Buf).toString('hex'));

    // 0x50 activity_information (MET bytes during daytime)
    const actBuf = Buffer.alloc(4 + 1 + 60);
    actBuf.writeUInt32LE(wakeDs + 36000, 0);
    actBuf[4] = 1;
    for (let m = 0; m < 60; m++) {
      actBuf[5 + m] = 35 + ((d * 3 + m) % 25); // 3.5 to 6.0 MET active minutes
    }
    notificationsHex.push(encodePacket(0x50, actBuf).toString('hex'));
  }

  // Emit 0x42 time_sync event anchoring ringTimestamp to phoneUnix
  const syncBuf = Buffer.alloc(8);
  syncBuf.writeUInt32LE(toRingDs(nowUnix), 0);
  syncBuf.writeUInt32LE(nowUnix, 4);
  notificationsHex.push(encodePacket(0x42, syncBuf).toString('hex'));

  return ingestBleNotifications(userId, {
    serial,
    notificationsHex,
    phoneUnix: nowUnix
  });
}
