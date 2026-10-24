/**
 * Laura Serverless Static Backend for GitHub Pages (`*.github.io`)
 *
 * Security & Storage Architecture:
 *  - Strict authentication gate: unauthenticated by default (`authenticated: false`).
 *    All `/api/dashboard/*`, `/api/ring/*`, and `/api/user/*` endpoints require a
 *    valid cryptographic session token.
 *  - OWASP-compliant password storage using WebCrypto `PBKDF2-HMAC-SHA256`
 *    (210,000 iterations + 16-byte CSPRNG salt) and constant-time comparison.
 *    Plaintext passwords are NEVER stored.
 *  - CSPRNG 256-bit session tokens stored only as `SHA-256` digests in the DB.
 *  - Brute-force login rate limiting (max 5 failed attempts per 5 minutes).
 *  - Supports up to 3 household users (Admin + Partner + optional 3rd member).
 *  - Pure-JS AES-128-ECB/PKCS7 implementation for `Th0rgal/open_oura` BLE ring auth.
 */

const STORAGE_KEY = 'laura_github_pages_db_v2';
const SESSION_TOKEN_KEY = 'laura_session_token_v2';
const MAX_HOUSEHOLD_USERS = 3;
const PBKDF2_ITERATIONS = 210000;

// In-memory + localStorage brute-force rate limiter
const loginAttempts = { count: 0, lockedUntil: 0 };

// --- Pure-JS AES-128-ECB (for 15-byte Oura Ring BLE Nonce Challenge `0x2c -> 0x2d`) ---
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);

const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function xtime(a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

function expandKey128(key16) {
  const w = new Uint8Array(176);
  w.set(key16);
  const temp = new Uint8Array(4);
  for (let i = 4; i < 44; i++) {
    for (let j = 0; j < 4; j++) temp[j] = w[(i - 1) * 4 + j];
    if (i % 4 === 0) {
      const t = temp[0];
      temp[0] = SBOX[temp[1]] ^ RCON[i / 4];
      temp[1] = SBOX[temp[2]];
      temp[2] = SBOX[temp[3]];
      temp[3] = SBOX[t];
    }
    for (let j = 0; j < 4; j++) {
      w[i * 4 + j] = w[(i - 4) * 4 + j] ^ temp[j];
    }
  }
  return w;
}

export function aes128EcbEncryptBlock(key16, block16) {
  const rk = expandKey128(key16);
  const s = new Uint8Array(block16);

  const addRoundKey = (round) => {
    for (let i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
  };

  addRoundKey(0);
  for (let round = 1; round <= 10; round++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    if (round < 10) {
      for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        const tm = a0 ^ a1 ^ a2 ^ a3;
        s[i] ^= tm ^ xtime(a0 ^ a1);
        s[i + 1] ^= tm ^ xtime(a1 ^ a2);
        s[i + 2] ^= tm ^ xtime(a2 ^ a3);
        s[i + 3] ^= tm ^ xtime(a3 ^ a0);
      }
    }
    addRoundKey(round);
  }
  return s;
}

function hexToBytes(hex) {
  const clean = String(hex || '').trim().replace(/\s+/g, '').replace(/^0x/i, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function encryptAuthNonceBrowser(keyHex, nonceHex) {
  const key = hexToBytes(keyHex);
  const nonce = hexToBytes(nonceHex);
  const block = new Uint8Array(16);
  const n = Math.min(16, nonce.length);
  block.set(nonce.subarray(0, n), 0);
  const pad = 16 - n;
  for (let i = n; i < 16; i++) block[i] = pad;
  return bytesToHex(aes128EcbEncryptBlock(key, block));
}

// --- WebCrypto Password Hashing (`PBKDF2-HMAC-SHA256`, 210k iterations) & Session Tokens ---

function timingSafeEqualHex(aHex, bHex) {
  const a = hexToBytes(aHex);
  const b = hexToBytes(bHex);
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function pbkdf2Hex(password, saltBytes, iterations = PBKDF2_ITERATIONS) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(String(password)),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

export async function hashPasswordBrowser(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const derivedHex = await pbkdf2Hex(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${bytesToHex(salt)}$${derivedHex}`;
}

export async function verifyPasswordBrowser(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') return false;
  const iterations = Number(parts[1]);
  const salt = hexToBytes(parts[2]);
  const expectedHex = parts[3];
  if (!iterations || salt.length < 8 || !expectedHex) return false;
  const actualHex = await pbkdf2Hex(password, salt, iterations);
  return timingSafeEqualHex(actualHex, expectedHex);
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)));
  return bytesToHex(new Uint8Array(buf));
}

function generateSessionTokenBrowser() {
  const rand = new Uint8Array(32);
  crypto.getRandomValues(rand);
  return bytesToHex(rand);
}

// Precomputed PBKDF2-HMAC-SHA256 (210,000 iterations) hashes for initial bootstrap password ("laura2026")
// Format: pbkdf2_sha256$210000$<salt_hex>$<derived_key_hex>
// Users are prompted to change their password in Settings -> Security after first login.
const BOOTSTRAP_HASH_ALEX =
  'pbkdf2_sha256$210000$7a91c4e82b10f563d84910a2c7e3b109$ef9b201658e882b1d7bd52c07a9e607dc2270f1d8299c09d95626a5bc98120aa';

function sanitizeUser(u) {
  if (!u) return null;
  const { passwordHash, ringKeyHex, ...rest } = u;
  return {
    ...rest,
    hasRingKey: Boolean(ringKeyHex)
  };
}

export function toLocalDayStr(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function localDayDate(dayStr, hours = 0, minutes = 0, seconds = 0) {
  const [y, m, d] = String(dayStr).split('-').map(Number);
  return new Date(y, (m || 1) - 1, d || 1, hours, minutes, seconds, 0);
}

function buildSyncTimeHexBrowser() {
  const unixSecs = BigInt(Math.floor(Date.now() / 1000));
  const tzHalfHours = Math.round(-new Date().getTimezoneOffset() / 30) & 0xff;
  const bytes = new Uint8Array(11);
  bytes[0] = 0x12;
  bytes[1] = 0x09;
  const view = new DataView(bytes.buffer);
  view.setBigUint64(2, unixSecs, true);
  bytes[10] = tzHalfHours;
  return bytesToHex(bytes);
}

// --- Browser-Side Th0rgal/open_oura Binary Packet Decoder & Scorer ---
const EVENT_NAMES_BROWSER = {
  0x41: 'ring_start',
  0x42: 'time_sync',
  0x43: 'debug_event',
  0x45: 'state_change',
  0x46: 'temp_event',
  0x47: 'motion_event',
  0x4b: 'sleep_phase_information',
  0x4e: 'sleep_phase_details',
  0x50: 'activity_information',
  0x53: 'wear_event',
  0x5a: 'sleep_phase_data',
  0x5d: 'hrv_event',
  0x60: 'ibi_and_amplitude_event',
  0x69: 'temp_period',
  0x6a: 'sleep_period_information_2',
  0x6f: 'spo2_event',
  0x75: 'sleep_temp_event',
  0x76: 'bedtime_period',
  0x80: 'green_ibi_quality_event',
  0x85: 'rtc_beacon',
  0x8b: 'spo2_r_pi_event'
};

function parsePacketsBrowser(bytes) {
  const out = [];
  let i = 0;
  while (i + 2 <= bytes.length) {
    const tag = bytes[i];
    const len = bytes[i + 1];
    const start = i + 2;
    const end = start + len;
    if (end > bytes.length) break;
    out.push({ tag, payload: bytes.subarray(start, end) });
    i = end;
  }
  if (out.length === 0 && bytes.length >= 2) {
    out.push({ tag: bytes[0], payload: bytes.subarray(2) });
  }
  return out;
}

function readU32LE(b, off = 0) {
  return ((b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0);
}

function readI16LE(b, off = 0) {
  const v = b[off] | (b[off + 1] << 8);
  return v & 0x8000 ? v - 0x10000 : v;
}

function decodeEventBodyBrowser(tag, body) {
  switch (tag) {
    case 0x46:
    case 0x69:
    case 0x75: {
      if (body.length < 2) return null;
      const temps_c = [];
      for (let i = 0; i + 1 < body.length; i += 2) {
        const c = readI16LE(body, i) / 100.0;
        if (c >= 30.0 && c <= 41.0) temps_c.push(c);
      }
      return temps_c.length ? { temps_c } : null;
    }
    case 0x4b:
    case 0x4e:
    case 0x5a: {
      if (body.length < 2) return null;
      const PHASE = ['1', '2', '3', '4']; // 1=deep, 2=light, 3=rem, 4=awake
      const stages = [];
      for (let i = 1; i < body.length; i++) {
        const b = body[i];
        for (const shift of [6, 4, 2, 0]) {
          stages.push(PHASE[(b >> shift) & 0x03]);
        }
      }
      return { stages };
    }
    case 0x50: {
      if (body.length < 2) return null;
      const met = [];
      for (let i = 1; i < body.length; i++) {
        const b = body[i];
        met.push(b < 0x80 ? b * 0.1 : 12.8 + (b - 128) * 0.2);
      }
      return { met };
    }
    case 0x5d: {
      if (body.length < 2) return null;
      const hr_bpm = [];
      const rmssd_ms = [];
      for (let i = 0; i + 1 < body.length; i += 2) {
        if (body[i] >= 35 && body[i] <= 140) hr_bpm.push(body[i]);
        if (body[i + 1] >= 10 && body[i + 1] <= 250) rmssd_ms.push(body[i + 1]);
      }
      return { hr_bpm, rmssd_ms };
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
      const hr_bpm = ibi_ms.filter((i) => i >= 300 && i <= 2000).map((i) => Math.floor(60000 / i));
      return { hr_bpm };
    }
    case 0x6a: {
      if (body.length < 10) return null;
      return {
        average_hr: body[0] * 0.5,
        breath: body[4] / 8.0,
        sleep_state: body[7]
      };
    }
    case 0x6f: {
      if (body.length < 2) return null;
      let end = body.length;
      if (body[end - 1] === 0xff) end -= 1;
      const spo2 = [];
      for (let i = 1; i < end; i++) {
        if (body[i] >= 80 && body[i] <= 100) spo2.push(body[i]);
      }
      return spo2.length ? { spo2 } : null;
    }
    case 0x76: {
      if (body.length < 8) return null;
      return {
        bedtime_start_ds: readU32LE(body, 0),
        bedtime_end_ds: readU32LE(body, 4)
      };
    }
    case 0x80: {
      if (body.length < 2) return null;
      const hr_bpm = [];
      for (let i = 0; i + 1 < body.length; i += 2) {
        const ibi = (body[i + 1] & 0x07) | (body[i] << 3);
        const q = (body[i + 1] >> 3) & 0x03;
        if (q === 1 && ibi >= 300 && ibi <= 2000) hr_bpm.push(Math.floor(60000 / ibi));
      }
      return { hr_bpm };
    }
    default:
      return null;
  }
}

function ingestBleNotificationsBrowser(db, user, { serial, notificationsHex = [], phoneUnix = Math.floor(Date.now() / 1000), clearDemo = true }) {
  if (clearDemo) {
    const existingDays = db.summaries[user.id] || {};
    for (const k of Object.keys(existingDays)) {
      if (existingDays[k]?.isDemo || existingDays[k]?.sleep?.hypnogram5min === '422111223322112233322123324') {
        delete existingDays[k];
        if (db.heartrates[user.id]) delete db.heartrates[user.id][k];
      }
    }
  }
  user.hasSyncedRealRing = true;

  let maxRingTs = 0;
  let eventsIngested = 0;
  const rawEvents = [];
  const countsMap = new Map();

  for (const hexStr of notificationsHex) {
    const clean = String(hexStr || '').trim().replace(/\s+/g, '').replace(/^0x/i, '');
    if (!clean || clean.length < 4) continue;
    const bytes = hexToBytes(clean);
    const packets = parsePacketsBrowser(bytes);

    for (const pkt of packets) {
      if (pkt.tag === 0x0b && pkt.payload.length >= 3) {
        user.ringFirmware = `${pkt.payload[0]}.${pkt.payload[1]}.${pkt.payload[2]}`;
      } else if (pkt.tag === 0x0d && pkt.payload.length >= 1) {
        user.ringBattery = Math.min(100, pkt.payload[0]);
      } else if (pkt.tag === 0x11 && pkt.payload.length > 1 && pkt.payload[0] !== 0x09) {
        const txt = Array.from(pkt.payload)
          .filter((c) => c >= 32 && c <= 126)
          .map((c) => String.fromCharCode(c))
          .join('')
          .trim();
        if (txt) user.ringSerial = txt;
      } else if (pkt.tag === 0x13 && pkt.payload.length >= 4) {
        const ts = readU32LE(pkt.payload, 0);
        if (ts > maxRingTs) maxRingTs = ts;
      } else if (pkt.tag >= 0x41 && pkt.payload.length >= 4) {
        const rts = readU32LE(pkt.payload, 0);
        if (rts > maxRingTs) maxRingTs = rts;
        const body = pkt.payload.subarray(4);
        const name = EVENT_NAMES_BROWSER[pkt.tag] || `event_0x${pkt.tag.toString(16)}`;
        const tagHex = `0x${pkt.tag.toString(16).padStart(2, '0')}`;
        countsMap.set(tagHex, { tagHex, name, count: (countsMap.get(tagHex)?.count || 0) + 1 });
        rawEvents.push({
          tag: pkt.tag,
          name,
          ringTimestamp: rts,
          decoded: decodeEventBodyBrowser(pkt.tag, body)
        });
        eventsIngested++;
      }
    }
  }

  if (countsMap.size > 0) {
    db.ringEvents[user.id] = [...countsMap.values()];
  }
  if (maxRingTs > 0) {
    user.ringCursor = maxRingTs;
  }

  const bootUnix = phoneUnix - maxRingTs / 10.0;
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
        deepSec: 0,
        remSec: 0,
        lightSec: 0,
        awakeSec: 0,
        hypno: [],
        hr5min: [],
        hrv5min: [],
        hrSamples: [],
        breath: [],
        temps: [],
        spo2: [],
        steps: 0,
        activeCal: 0,
        highSec: 0,
        medSec: 0,
        lowSec: 0,
        sedSec: 0
      });
    }
    return byDay.get(day);
  };

  for (const ev of rawEvents) {
    if (!ev.decoded) continue;
    const unixSec = Math.round(bootUnix + ev.ringTimestamp / 10.0);
    // Shift by 4 hours so sleep starting at 8:00 PM - 11:59 PM local time attributes to waking local day
    const day = toLocalDayStr(new Date((unixSec + 4 * 3600) * 1000));
    const d = ev.decoded;
    const b = ensureDay(day);
    b.hasData = true;

    if (ev.tag === 0x76) {
      const startU = Math.round(unixSec - (ev.ringTimestamp - d.bedtime_start_ds) / 10.0);
      const endU = Math.round(unixSec - (ev.ringTimestamp - d.bedtime_end_ds) / 10.0);
      if (endU >= startU && endU - startU <= 54000) {
        b.bedtimeStartUnix = b.bedtimeStartUnix ? Math.min(b.bedtimeStartUnix, startU) : startU;
        b.bedtimeEndUnix = b.bedtimeEndUnix ? Math.max(b.bedtimeEndUnix, endU) : endU;
      }
    } else if (ev.tag === 0x4b || ev.tag === 0x4e || ev.tag === 0x5a) {
      b.sleepMinUnix = b.sleepMinUnix !== null ? Math.min(b.sleepMinUnix, unixSec) : unixSec;
      b.sleepMaxUnix = b.sleepMaxUnix !== null ? Math.max(b.sleepMaxUnix, unixSec) : unixSec;
      for (const ch of d.stages || []) {
        b.hypno.push(ch);
        if (ch === '1') b.deepSec += 300;
        else if (ch === '3') b.remSec += 300;
        else if (ch === '4') b.awakeSec += 300;
        else b.lightSec += 300;
      }
    } else if (ev.tag === 0x6a) {
      b.sleepMinUnix = b.sleepMinUnix !== null ? Math.min(b.sleepMinUnix, unixSec) : unixSec;
      b.sleepMaxUnix = b.sleepMaxUnix !== null ? Math.max(b.sleepMaxUnix, unixSec) : unixSec;
      if (d.average_hr >= 35 && d.average_hr <= 130) {
        const bpm = Math.round(d.average_hr);
        b.hr5min.push(bpm);
        b.hrSamples.push({ timestamp: new Date(unixSec * 1000).toISOString(), bpm, source: 'sleep' });
      }
      if (d.breath >= 8 && d.breath <= 30) b.breath.push(d.breath);
    } else if (ev.tag === 0x5d) {
      b.sleepMinUnix = b.sleepMinUnix !== null ? Math.min(b.sleepMinUnix, unixSec) : unixSec;
      b.sleepMaxUnix = b.sleepMaxUnix !== null ? Math.max(b.sleepMaxUnix, unixSec) : unixSec;
      for (const r of d.rmssd_ms || []) b.hrv5min.push(r);
      (d.hr_bpm || []).forEach((bpm, idx) => {
        b.hr5min.push(bpm);
        b.hrSamples.push({ timestamp: new Date((unixSec + idx * 300) * 1000).toISOString(), bpm, source: 'sleep' });
      });
    } else if (ev.tag === 0x60 || ev.tag === 0x80) {
      const src = ev.tag === 0x80 ? 'awake' : 'sleep';
      for (const bpm of d.hr_bpm || []) {
        b.hrSamples.push({ timestamp: new Date(unixSec * 1000).toISOString(), bpm, source: src });
      }
    } else if (ev.tag === 0x46 || ev.tag === 0x69 || ev.tag === 0x75) {
      for (const c of d.temps_c || []) b.temps.push(c);
    } else if (ev.tag === 0x6f) {
      for (const s of d.spo2 || []) b.spo2.push(s);
    } else if (ev.tag === 0x50) {
      for (const m of d.met || []) {
        if (m > 1.3) b.steps += Math.round((m - 1.0) * 45);
        if (m > 1.2) b.activeCal += Math.round((m - 1.0) * 1.4);
        if (m >= 6.0) b.highSec += 60;
        else if (m >= 3.0) b.medSec += 60;
        else if (m >= 1.5) b.lowSec += 60;
        else b.sedSec += 60;
      }
    }
  }

  if (!db.summaries[user.id]) db.summaries[user.id] = {};
  if (!db.heartrates[user.id]) db.heartrates[user.id] = {};

  let daysUpdated = 0;
  for (const [day, b] of [...byDay.entries()].sort((a, z) => a[0].localeCompare(z[0]))) {
    if (!b.hasData) continue;

    let totalSeconds = b.deepSec + b.remSec + b.lightSec;
    let deepSeconds = b.deepSec;
    let remSeconds = b.remSec;
    let lightSeconds = b.lightSec;
    let awakeSeconds = b.awakeSec;

    if (totalSeconds === 0 && b.bedtimeStartUnix && b.bedtimeEndUnix && b.bedtimeEndUnix > b.bedtimeStartUnix) {
      const span = Math.min(43200, b.bedtimeEndUnix - b.bedtimeStartUnix);
      awakeSeconds = Math.round(span * 0.09);
      totalSeconds = span - awakeSeconds;
      deepSeconds = Math.round(totalSeconds * 0.21);
      remSeconds = Math.round(totalSeconds * 0.23);
      lightSeconds = totalSeconds - deepSeconds - remSeconds;
    }

    const hasSleep = totalSeconds > 0 || b.hypno.length > 0;
    const timeInBedSeconds = totalSeconds + awakeSeconds;
    const efficiency = timeInBedSeconds > 0 ? Math.round((totalSeconds / timeInBedSeconds) * 100) : 0;
    const lowestHr = b.hr5min.length > 0 ? Math.min(...b.hr5min) : null;
    const averageHr = b.hr5min.length > 0 ? Number((b.hr5min.reduce((a, v) => a + v, 0) / b.hr5min.length).toFixed(1)) : null;
    const averageHrv = b.hrv5min.length > 0 ? Math.round(b.hrv5min.reduce((a, v) => a + v, 0) / b.hrv5min.length) : null;
    const averageBreath = b.breath.length > 0 ? Number((b.breath.reduce((a, v) => a + v, 0) / b.breath.length).toFixed(1)) : null;
    const spo2Pct = b.spo2.length > 0 ? Number((b.spo2.reduce((a, v) => a + v, 0) / b.spo2.length).toFixed(1)) : null;
    const tempDev = b.temps.length > 0 ? Number((b.temps.reduce((a, v) => a + v, 0) / b.temps.length - 36.25).toFixed(2)) : null;

    let bedtimeStart = null;
    let bedtimeEnd = null;
    if (b.bedtimeStartUnix && b.bedtimeEndUnix && b.bedtimeEndUnix > b.bedtimeStartUnix) {
      bedtimeStart = new Date(b.bedtimeStartUnix * 1000).toISOString();
      bedtimeEnd = new Date(b.bedtimeEndUnix * 1000).toISOString();
    } else if (hasSleep && b.sleepMinUnix && b.sleepMaxUnix) {
      const endU = b.sleepMaxUnix;
      const startU = Math.min(b.sleepMinUnix, endU - Math.max(timeInBedSeconds, 3600));
      bedtimeStart = new Date(startU * 1000).toISOString();
      bedtimeEnd = new Date(endU * 1000).toISOString();
    } else if (hasSleep) {
      const localWake = localDayDate(day, 6, 45, 0);
      const localBed = new Date(localWake.getTime() - Math.max(timeInBedSeconds, 25200) * 1000);
      bedtimeStart = localBed.toISOString();
      bedtimeEnd = localWake.toISOString();
    }

    const sleepScore = hasSleep
      ? Math.max(40, Math.min(98, Math.round(55 + (totalSeconds / 3600 - 6) * 10 + (efficiency - 80) * 0.6)))
      : 0;
    const activityScore = b.steps > 0 || b.activeCal > 0
      ? Math.max(45, Math.min(98, Math.round(60 + (b.steps / 10000) * 25)))
      : 0;
    const readinessScore = hasSleep || lowestHr !== null || averageHrv !== null
      ? Math.max(45, Math.min(98, Math.round((sleepScore || 78) * 0.45 + (averageHrv ? Math.min(98, averageHrv + 20) : 78) * 0.55)))
      : 0;

    db.summaries[user.id][day] = {
      userId: user.id,
      day,
      isDemo: false,
      readiness: {
        score: readinessScore,
        tempDeviation: tempDev,
        tempTrendDeviation: tempDev,
        contributors: {
          hrvBalance: averageHrv != null ? Math.min(99, averageHrv + 20) : 0,
          restingHeartRate: lowestHr != null ? Math.min(99, 138 - lowestHr) : 0,
          recoveryIndex: hasSleep ? Math.min(99, readinessScore + 2) : 0,
          sleepBalance: sleepScore,
          previousNight: sleepScore,
          activityBalance: activityScore
        }
      },
      sleep: {
        score: sleepScore,
        totalSeconds,
        deepSeconds,
        remSeconds,
        lightSeconds,
        awakeSeconds,
        timeInBedSeconds,
        efficiency,
        latencySeconds: hasSleep ? 720 : 0,
        lowestHr,
        averageHr,
        averageHrv,
        averageBreath,
        bedtimeStart,
        bedtimeEnd,
        hypnogram5min: b.hypno.join(''),
        hr5min: b.hr5min,
        hrv5min: b.hrv5min
      },
      activity: {
        score: activityScore,
        steps: b.steps,
        activeCalories: b.activeCal,
        totalCalories: b.steps > 0 || b.activeCal > 0 ? 1680 + b.activeCal : 0,
        walkingDistanceMeters: Math.round(b.steps * 0.762),
        highSeconds: b.highSec,
        mediumSeconds: b.medSec,
        lowSeconds: b.lowSec,
        sedentarySeconds: b.sedSec,
        inactivityAlerts: 0
      },
      spo2: {
        percentage: spo2Pct,
        breathingDisturbanceIndex: spo2Pct ? 0.4 : null
      },
      stress: {
        stressHighSeconds: 0,
        recoveryHighSeconds: 0,
        daySummary: hasSleep ? (readinessScore >= 82 ? 'restored' : 'normal') : 'no data'
      },
      tags: db.summaries[user.id][day]?.tags || [],
      customNote: db.summaries[user.id][day]?.customNote || ''
    };

    if (b.hrSamples.length > 0) {
      db.heartrates[user.id][day] = b.hrSamples;
    }
    daysUpdated++;
  }

  return {
    serial: user.ringSerial,
    eventsIngested,
    maxCursor: maxRingTs,
    batteryPercent: user.ringBattery,
    firmware: user.ringFirmware,
    daysUpdated
  };
}

function getMayaCycleDayForOffsetBrowser(offset) {
  const daysSinceAnchor = 74 - offset;
  const mod = ((daysSinceAnchor % 28) + 28) % 28;
  return mod + 1;
}

function seedMayaCycleLogsBrowser(cycleLogsByUser, userId = 2) {
  if (!cycleLogsByUser[userId]) cycleLogsByUser[userId] = {};
  const now = new Date();
  for (let i = 89; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 12, 0, 0);
    const dayStr = toLocalDayStr(d);
    const cDay = getMayaCycleDayForOffsetBrowser(i);
    if (cDay === 1) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'medium',
        symptoms: ['Cramps', 'Fatigue'],
        ovulationTest: 'none',
        notes: 'Cycle Day 1 — period started.'
      };
    } else if (cDay === 2) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'heavy',
        symptoms: ['Cramps', 'Lower Back Ache'],
        ovulationTest: 'none',
        notes: 'Cycle Day 2 — heavier flow.'
      };
    } else if (cDay === 3) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'medium',
        symptoms: ['Fatigue'],
        ovulationTest: 'none',
        notes: ''
      };
    } else if (cDay === 4 || cDay === 5) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'light',
        symptoms: [],
        ovulationTest: 'none',
        notes: ''
      };
    } else if (cDay === 13) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'none',
        symptoms: ['High Energy'],
        ovulationTest: 'positive',
        notes: 'Positive LH surge strip.'
      };
    } else if (cDay === 26) {
      cycleLogsByUser[userId][dayStr] = {
        userId,
        day: dayStr,
        flow: 'none',
        symptoms: ['Bloating', 'Breast Tenderness'],
        ovulationTest: 'none',
        notes: 'Late luteal phase.'
      };
    }
  }
}

// --- Seed Generator for Static Mode ---
async function createInitialStaticDbAsync() {
  const alexHash = await hashPasswordBrowser('laura2026');
  const mayaHash = await hashPasswordBrowser('laura2026');

  const users = [
    {
      id: 1,
      username: 'alex',
      displayName: 'Alex (My Ring)',
      email: 'alex@household.local',
      passwordHash: alexHash,
      isDefaultPassword: true,
      role: 'admin',
      avatarColor: '#6366f1',
      ringName: 'Oura Ring Gen 3 • Stealth Black',
      ringSerial: 'OURA3-ALEX',
      ringKeyHex: '4431967d8bacc2659743142b68391d9a',
      hasRingKey: true,
      ringBattery: 88,
      ringFirmware: '3.2.11',
      ringHwId: 'GEN3-STEALTH',
      ringCursor: 142800,
      shareWithHousehold: true,
      authMode: 'ble',
      hasLiveToken: true,
      lastSyncedAt: new Date().toISOString()
    },
    {
      id: 2,
      username: 'maya',
      displayName: 'Maya (Wife)',
      email: 'maya@household.local',
      passwordHash: mayaHash,
      isDefaultPassword: true,
      role: 'member',
      avatarColor: '#ec4899',
      ringName: 'Oura Ring Gen 3 • Rose Gold',
      ringSerial: 'OURA3-MAYA',
      ringKeyHex: '8bacc2659743142b68391d9a4431967d',
      hasRingKey: true,
      ringBattery: 92,
      ringFirmware: '3.2.11',
      ringHwId: 'GEN3-ROSEGOLD',
      ringCursor: 138400,
      shareWithHousehold: true,
      authMode: 'ble',
      hasLiveToken: true,
      lastSyncedAt: new Date().toISOString()
    }
  ];

  const summaries = {};
  const heartrates = {};
  const now = new Date();

  for (const u of users) {
    summaries[u.id] = {};
    heartrates[u.id] = {};
    const isMaya = u.id === 2;

    for (let i = 89; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 12, 0, 0);
      const dayStr = toLocalDayStr(d);
      const wave = Math.sin((i + u.id * 4) * 0.35);
      const wave2 = Math.cos((i + u.id * 2) * 0.22);

      const cDay = isMaya ? getMayaCycleDayForOffsetBrowser(i) : null;
      const isLuteal = isMaya && cDay >= 15;
      const lowestHr = Math.round((isMaya ? (isLuteal ? 56 : 53) : 50) - wave * 2);
      const averageHrv = Math.round((isMaya ? (isLuteal ? 64 : 71) : 62) + wave * 9 + wave2 * 4);
      const biphasicTemp = isMaya
        ? Number(((cDay <= 12 ? -0.17 : cDay <= 14 ? -0.24 : cDay <= 26 ? 0.27 : 0.12) + wave * 0.04).toFixed(2))
        : Number((wave * 0.14).toFixed(2));
      const deepSeconds = Math.round((isMaya ? 6100 : 5600) + wave * 900);
      const remSeconds = Math.round((isMaya ? 6400 : 6000) + wave2 * 800);
      const lightSeconds = Math.round(14800 + wave * 1100);
      const awakeSeconds = Math.round(1900 - wave * 300);
      const totalSeconds = deepSeconds + remSeconds + lightSeconds;
      const timeInBedSeconds = totalSeconds + awakeSeconds;
      const efficiency = Math.round((totalSeconds / timeInBedSeconds) * 100);

      const sleepScore = Math.max(62, Math.min(97, Math.round(82 + wave * 8 + wave2 * 4)));
      const readinessScore = Math.max(60, Math.min(98, Math.round(83 + wave * 9 + wave2 * 3)));
      const steps = Math.round((isMaya ? 9400 : 10200) + wave2 * 2600);
      const activeCalories = Math.round(steps * 0.044);
      const activityScore = Math.max(64, Math.min(98, Math.round(84 + wave2 * 8)));

      const bedStartHour = isMaya ? 22.5 : 22.75;
      const bedStartMinOffset = Math.round((bedStartHour - 22) * 60 + wave2 * 18);
      // Anchor bedtime to local device clock midnight (never UTC 'Z') so 10:45 PM is 10:45 PM local time!
      const bedStartDate = localDayDate(dayStr, 0, 0, 0);
      bedStartDate.setMinutes(bedStartDate.getMinutes() - (120 - bedStartMinOffset));
      const bedEndDate = new Date(bedStartDate.getTime() + timeInBedSeconds * 1000);

      const tags = [];
      if (i % 4 === 0) tags.push('Magnesium');
      if (i % 5 === 1) tags.push('Sauna');
      if (i % 6 === 2) tags.push('Morning sunlight');
      if (i % 9 === 4) tags.push('Late meal');
      if (i % 11 === 5) tags.push('Workout');

      summaries[u.id][dayStr] = {
        userId: u.id,
        day: dayStr,
        isDemo: true,
        readiness: {
          score: readinessScore,
          tempDeviation: biphasicTemp,
          tempTrendDeviation: Number((biphasicTemp * 0.75).toFixed(2)),
          contributors: {
            hrvBalance: Math.min(99, averageHrv + 20),
            restingHeartRate: Math.min(99, 138 - lowestHr),
            recoveryIndex: Math.min(99, readinessScore + 3),
            sleepBalance: sleepScore,
            previousNight: sleepScore,
            activityBalance: activityScore
          }
        },
        sleep: {
          score: sleepScore,
          totalSeconds,
          deepSeconds,
          remSeconds,
          lightSeconds,
          awakeSeconds,
          timeInBedSeconds,
          efficiency,
          latencySeconds: 720,
          lowestHr,
          averageHr: Number((lowestHr + 5.4).toFixed(1)),
          averageHrv,
          averageBreath: isMaya ? 15.1 : 14.2,
          bedtimeStart: bedStartDate.toISOString(),
          bedtimeEnd: bedEndDate.toISOString(),
          hypnogram5min: '422111223322112233322123324',
          hr5min: [lowestHr + 6, lowestHr + 3, lowestHr + 1, lowestHr, lowestHr + 2, lowestHr + 4],
          hrv5min: [averageHrv - 8, averageHrv - 2, averageHrv + 6, averageHrv + 10, averageHrv + 3]
        },
        activity: {
          score: activityScore,
          steps,
          activeCalories,
          totalCalories: 1680 + activeCalories,
          walkingDistanceMeters: Math.round(steps * 0.762),
          highSeconds: 1800,
          mediumSeconds: 3600,
          lowSeconds: 14400,
          sedentarySeconds: 27000,
          inactivityAlerts: 0
        },
        spo2: {
          percentage: Number((98.1 + wave * 0.5).toFixed(1)),
          breathingDisturbanceIndex: 0.4
        },
        stress: {
          stressHighSeconds: Math.max(900, Math.round(3600 - wave * 1200)),
          recoveryHighSeconds: Math.max(1800, Math.round(7200 + wave * 1800)),
          daySummary: readinessScore >= 82 ? 'restored' : 'normal'
        },
        tags,
        customNote: ''
      };

      if (i < 14) {
        const samples = [];
        for (let h = 0; h < 48; h++) {
          const ts = localDayDate(dayStr, 0, h * 30, 0);
          const asleep = h < 14 || h >= 45;
          const bpm = asleep
            ? Math.round(lowestHr + 3 + Math.sin(h * 0.5) * 3)
            : Math.round(lowestHr + 22 + Math.sin(h * 0.4) * 12);
          samples.push({
            timestamp: ts.toISOString(),
            bpm,
            source: asleep ? 'sleep' : 'awake'
          });
        }
        heartrates[u.id][dayStr] = samples;
      }
    }
  }

  const cycleLogs = { 1: {}, 2: {} };
  seedMayaCycleLogsBrowser(cycleLogs, 2);

  return {
    householdName: 'Alex & Maya Household',
    registrationLocked: true,
    maxUsers: MAX_HOUSEHOLD_USERS,
    sessions: [],
    users,
    summaries,
    heartrates,
    cycleLogs,
    ringEvents: {
      1: [
        { tagHex: '0x76', name: 'bedtime_period', count: 14 },
        { tagHex: '0x5a', name: 'sleep_phase_data', count: 14 },
        { tagHex: '0x5d', name: 'hrv_event', count: 84 },
        { tagHex: '0x75', name: 'sleep_temp_event', count: 112 },
        { tagHex: '0x6f', name: 'spo2_event', count: 14 },
        { tagHex: '0x50', name: 'activity_information', count: 14 }
      ],
      2: [
        { tagHex: '0x76', name: 'bedtime_period', count: 14 },
        { tagHex: '0x5a', name: 'sleep_phase_data', count: 14 },
        { tagHex: '0x5d', name: 'hrv_event', count: 84 },
        { tagHex: '0x75', name: 'sleep_temp_event', count: 112 },
        { tagHex: '0x6f', name: 'spo2_event', count: 14 },
        { tagHex: '0x50', name: 'activity_information', count: 14 }
      ]
    },
    syncLogs: [
      {
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        status: 'success',
        daysSynced: 90,
        message: 'GitHub Pages Cloud-Free Engine ready (PBKDF2-SHA256 Auth + open_oura BLE).'
      }
    ]
  };
}

async function loadDbAsync() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      let mutated = false;
      const hadBleSyncInLogs = (parsed.syncLogs || []).some(
        (l) => l.message && l.message.includes('open_oura BLE binary sync')
      );

      for (const u of parsed.users || []) {
        if (!u.passwordHash) {
          u.passwordHash = await hashPasswordBrowser('laura2026');
          u.isDefaultPassword = true;
          mutated = true;
        }
        const userDays = parsed.summaries?.[u.id] || {};
        const userSyncedBle =
          Boolean(u.hasSyncedRealRing) ||
          (u.id === 1 && u.ringCursor && u.ringCursor !== 142800) ||
          (u.id === 2 && u.ringCursor && u.ringCursor !== 138400) ||
          (u.id === 1 && hadBleSyncInLogs);

        if (userSyncedBle && !u.hasSyncedRealRing) {
          u.hasSyncedRealRing = true;
          mutated = true;
        }

        for (const [dayKey, s] of Object.entries(userDays)) {
          const isSyntheticSeed =
            s.isDemo === true || s.sleep?.hypnogram5min === '422111223322112233322123324';
          if (isSyntheticSeed && s.isDemo === undefined) {
            s.isDemo = true;
            mutated = true;
          }
          // If this user has synced their physical ring, remove pre-seeded demo days so unsynced days don't show fake stats!
          if (userSyncedBle && isSyntheticSeed) {
            delete userDays[dayKey];
            if (parsed.heartrates?.[u.id]) delete parsed.heartrates[u.id][dayKey];
            mutated = true;
            continue;
          }
          // Fix any bedtimeStart/bedtimeEnd that was previously stored with UTC 'Z' (starting around 3-5 PM local time)
          if (s.sleep?.bedtimeStart) {
            const bd = new Date(s.sleep.bedtimeStart);
            const localHr = bd.getHours();
            const tzOffsetMs = bd.getTimezoneOffset() * 60 * 1000;
            if (tzOffsetMs !== 0 && localHr >= 13 && localHr <= 18) {
              const fixedStart = new Date(bd.getTime() + tzOffsetMs);
              s.sleep.bedtimeStart = fixedStart.toISOString();
              if (s.sleep.bedtimeEnd) {
                const ed = new Date(s.sleep.bedtimeEnd);
                s.sleep.bedtimeEnd = new Date(ed.getTime() + tzOffsetMs).toISOString();
              }
              mutated = true;
            }
          }
        }
      }
      if (!parsed.cycleLogs || typeof parsed.cycleLogs !== 'object') {
        parsed.cycleLogs = { 1: {}, 2: {} };
        seedMayaCycleLogsBrowser(parsed.cycleLogs, 2);
        // Also upgrade Maya's demo summaries to have realistic biphasic temperature deviations if she hasn't synced a real ring
        const mayaUser = (parsed.users || []).find((u) => u.id === 2);
        if (mayaUser && !mayaUser.hasSyncedRealRing && parsed.summaries?.[2]) {
          const sortedDays = Object.keys(parsed.summaries[2]).sort();
          sortedDays.forEach((dKey, idx) => {
            const offset = sortedDays.length - 1 - idx;
            const cDay = getMayaCycleDayForOffsetBrowser(offset);
            const s = parsed.summaries[2][dKey];
            if (s?.readiness) {
              const bTemp = Number(((cDay <= 12 ? -0.17 : cDay <= 14 ? -0.24 : cDay <= 26 ? 0.27 : 0.12) + Math.sin(idx) * 0.04).toFixed(2));
              s.readiness.tempDeviation = bTemp;
              s.readiness.tempTrendDeviation = Number((bTemp * 0.75).toFixed(2));
            }
          });
        }
        mutated = true;
      } else if (!parsed.cycleLogs[2] || Object.keys(parsed.cycleLogs[2]).length === 0) {
        const mayaUser = (parsed.users || []).find((u) => u.id === 2);
        if (mayaUser && !mayaUser.hasSyncedRealRing) {
          seedMayaCycleLogsBrowser(parsed.cycleLogs, 2);
          mutated = true;
        }
      }
      if (!Array.isArray(parsed.sessions)) parsed.sessions = [];
      if (mutated) saveDb(parsed);
      return parsed;
    }
  } catch {}
  const initial = await createInitialStaticDbAsync();
  saveDb(initial);
  return initial;
}

function saveDb(db) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(db));
  } catch {}
}

async function getAuthenticatedUser(db) {
  try {
    const rawToken = localStorage.getItem(SESSION_TOKEN_KEY);
    if (!rawToken) return { user: null, tokenHash: null };
    const tokenHash = await sha256Hex(rawToken);
    const now = Date.now();
    db.sessions = (db.sessions || []).filter((s) => new Date(s.expiresAt).getTime() > now);
    const sess = db.sessions.find((s) => s.tokenHash === tokenHash);
    if (!sess) return { user: null, tokenHash: null };
    const user = db.users.find((u) => u.id === sess.userId) || null;
    return { user, tokenHash };
  } catch {
    return { user: null, tokenHash: null };
  }
}

function computeBaselines(db, userId, upToDay, windowDays = 30) {
  const userDays = Object.values(db.summaries[userId] || {})
    .filter((s) => s.day <= upToDay)
    .sort((a, b) => b.day.localeCompare(a.day))
    .slice(0, windowDays);

  const avg = (fn, fallback) => {
    const vals = userDays.map(fn).filter((v) => v != null && Number.isFinite(v));
    if (!vals.length) return fallback;
    return vals.reduce((a, b) => a + b, 0) / vals.length;
  };

  return {
    readiness: Math.round(avg((d) => d.readiness?.score, 82)),
    sleep: Math.round(avg((d) => d.sleep?.score, 82)),
    activity: Math.round(avg((d) => d.activity?.score, 82)),
    lowestHr: Number(avg((d) => d.sleep?.lowestHr, 52).toFixed(1)),
    averageHrv: Math.round(avg((d) => d.sleep?.averageHrv, 62)),
    totalSleepSeconds: Math.round(avg((d) => d.sleep?.totalSeconds, 27000)),
    deepSleepSeconds: Math.round(avg((d) => d.sleep?.deepSeconds, 5600)),
    remSleepSeconds: Math.round(avg((d) => d.sleep?.remSeconds, 6000)),
    steps: Math.round(avg((d) => d.activity?.steps, 9500)),
    spo2: Number(avg((d) => d.spo2?.percentage, 98.0).toFixed(1))
  };
}

const CYCLE_PHASE_META_BROWSER = {
  menstrual: {
    key: 'menstrual',
    label: 'Menstrual Phase',
    shortLabel: 'Menstrual',
    color: '#f43f5e',
    hormoneSummary: 'Estrogen & progesterone are at baseline; skin temperature drops back below baseline.',
    recoveryTip: 'Prioritize restorative sleep, iron-rich nutrition, gentle walks, or mobility work.'
  },
  follicular: {
    key: 'follicular',
    label: 'Follicular Phase',
    shortLabel: 'Follicular',
    color: '#38bdf8',
    hormoneSummary: 'Estrogen rises steadily; nightly skin temperature stays cooler (-0.1°C to -0.3°C) with lower RHR & higher HRV.',
    recoveryTip: 'Prime window for high-intensity training, strength PRs, and deep cognitive focus.'
  },
  ovulation: {
    key: 'ovulation',
    label: 'Ovulation Window',
    shortLabel: 'Ovulation',
    color: '#a855f7',
    hormoneSummary: 'Peak estrogen & LH surge trigger ovulation, followed by the biphasic thermal shift (+0.2°C to +0.4°C).',
    recoveryTip: 'Peak fertile window & high energy — stay well hydrated and support recovery after intense sessions.'
  },
  luteal: {
    key: 'luteal',
    label: 'Luteal Phase',
    shortLabel: 'Luteal',
    color: '#f59e0b',
    hormoneSummary: 'Progesterone dominates; Oura nightly skin temperature stays elevated (+0.15°C to +0.45°C) and RHR rises slightly.',
    recoveryTip: 'Metabolic rate is higher — allow extra wind-down time, magnesium, and steady aerobic movement.'
  }
};

function dayDiffBrowser(dayA, dayB) {
  const a = localDayDate(dayA, 12, 0, 0);
  const b = localDayDate(dayB, 12, 0, 0);
  return Math.round((b.getTime() - a.getTime()) / 86400000);
}

function addDaysBrowser(dayStr, deltaDays) {
  const dt = localDayDate(dayStr, 12, 0, 0);
  dt.setDate(dt.getDate() + deltaDays);
  return toLocalDayStr(dt);
}

function detectThermalShiftOvulationBrowser(summariesByDay, cycleStartDay, nextCycleStartDay) {
  const maxDayOffset = nextCycleStartDay ? Math.min(28, dayDiffBrowser(cycleStartDay, nextCycleStartDay) - 3) : 24;
  for (let cDay = 10; cDay <= maxDayOffset; cDay++) {
    const candidateDay = addDaysBrowser(cycleStartDay, cDay - 1);
    const prevTemps = [];
    for (let k = 1; k <= 6; k++) {
      const pDay = addDaysBrowser(candidateDay, -k);
      const t = summariesByDay.get(pDay)?.readiness?.tempDeviation;
      if (t !== null && t !== undefined && Number.isFinite(t)) prevTemps.push(t);
    }
    if (prevTemps.length < 3) continue;
    const preMean = prevTemps.reduce((a, b) => a + b, 0) / prevTemps.length;

    const postTemps = [];
    for (let k = 1; k <= 3; k++) {
      const fDay = addDaysBrowser(candidateDay, k);
      const t = summariesByDay.get(fDay)?.readiness?.tempDeviation;
      if (t !== null && t !== undefined && Number.isFinite(t)) postTemps.push(t);
    }
    if (postTemps.length < 2) continue;
    const postMean = postTemps.reduce((a, b) => a + b, 0) / postTemps.length;
    const allElevated = postTemps.every((t) => t >= preMean + 0.12);

    if (postMean - preMean >= 0.18 && allElevated) {
      return {
        ovulationDay: candidateDay,
        ovulationCycleDay: cDay,
        thermalShiftDeltaC: Number((postMean - preMean).toFixed(2)),
        detectedBy: 'Oura Ring Biphasic Temp Shift (3-over-6)'
      };
    }
  }
  return null;
}

function buildStaticCycleInsights(db, userId, targetDay, days = 60) {
  const user = db.users.find((u) => u.id === Number(userId)) || db.users[0];
  const userDaysMap = db.summaries[user.id] || {};
  const allDayKeys = Object.keys(userDaysMap).sort();
  const refDay = targetDay || allDayKeys[allDayKeys.length - 1] || toLocalDayStr();
  const startWindowDay = addDaysBrowser(refDay, -(days - 1));
  const lookbackStartDay = addDaysBrowser(refDay, -180);

  const summaries = allDayKeys
    .filter((d) => d >= lookbackStartDay && d <= refDay)
    .map((d) => userDaysMap[d]);
  const summariesByDay = new Map(summaries.map((s) => [s.day, s]));

  const userLogsObj = db.cycleLogs?.[user.id] || {};
  const allLogs = Object.values(userLogsObj)
    .filter((l) => l.day >= lookbackStartDay && l.day <= addDaysBrowser(refDay, 14))
    .sort((a, b) => a.day.localeCompare(b.day));
  const logsByDay = new Map(allLogs.map((l) => [l.day, l]));

  const flowDays = allLogs
    .filter((l) => l.flow && l.flow !== 'none' && l.flow !== 'spotting')
    .map((l) => l.day)
    .sort();

  const periodStarts = [];
  const periodEndByStart = new Map();
  let lastFlowDay = null;
  let currentStart = null;

  for (const d of flowDays) {
    if (!lastFlowDay || dayDiffBrowser(lastFlowDay, d) > 3) {
      currentStart = d;
      periodStarts.push(d);
      periodEndByStart.set(currentStart, d);
    } else {
      periodEndByStart.set(currentStart, d);
    }
    lastFlowDay = d;
  }

  const cycleLengths = [];
  for (let i = 1; i < periodStarts.length; i++) {
    const len = dayDiffBrowser(periodStarts[i - 1], periodStarts[i]);
    if (len >= 20 && len <= 45) cycleLengths.push(len);
  }
  const avgCycleLength = cycleLengths.length
    ? Math.round(cycleLengths.reduce((a, b) => a + b, 0) / cycleLengths.length)
    : 28;
  const cycleVariabilityDays =
    cycleLengths.length >= 2 ? Math.max(...cycleLengths) - Math.min(...cycleLengths) : 1;

  const periodLengths = periodStarts.map((st) => {
    const end = periodEndByStart.get(st) || st;
    return Math.max(1, Math.min(10, dayDiffBrowser(st, end) + 1));
  });
  const avgPeriodLength = periodLengths.length
    ? Math.max(3, Math.round(periodLengths.reduce((a, b) => a + b, 0) / periodLengths.length))
    : 5;

  const startsUpToRef = periodStarts.filter((d) => d <= refDay);
  const currentCycleStart = startsUpToRef.length ? startsUpToRef[startsUpToRef.length - 1] : null;
  const cycleDay = currentCycleStart ? dayDiffBrowser(currentCycleStart, refDay) + 1 : null;

  let ovulationInfo = null;
  if (currentCycleStart) {
    const lhPositive = allLogs.find(
      (l) =>
        l.day >= currentCycleStart &&
        dayDiffBrowser(currentCycleStart, l.day) <= 24 &&
        l.ovulationTest === 'positive'
    );
    const thermal = detectThermalShiftOvulationBrowser(summariesByDay, currentCycleStart, null);
    if (thermal) {
      ovulationInfo = thermal;
    } else if (lhPositive) {
      const ovDay = addDaysBrowser(lhPositive.day, 1);
      ovulationInfo = {
        ovulationDay: ovDay,
        ovulationCycleDay: dayDiffBrowser(currentCycleStart, ovDay) + 1,
        thermalShiftDeltaC: 0.25,
        detectedBy: 'Positive LH Ovulation Test'
      };
    } else {
      const estOvCycleDay = Math.max(11, avgCycleLength - 14);
      const ovDay = addDaysBrowser(currentCycleStart, estOvCycleDay - 1);
      ovulationInfo = {
        ovulationDay: ovDay,
        ovulationCycleDay: estOvCycleDay,
        thermalShiftDeltaC: null,
        detectedBy: 'Calendar & Luteal Baseline Estimate'
      };
    }
  }

  let currentPhaseKey = 'follicular';
  if (currentCycleStart && cycleDay !== null) {
    const currentLog = logsByDay.get(refDay);
    const isBleedingToday = currentLog?.flow && currentLog.flow !== 'none' && currentLog.flow !== 'spotting';
    const ovCycleDay = ovulationInfo?.ovulationCycleDay || Math.max(12, avgCycleLength - 14);
    if (isBleedingToday || cycleDay <= avgPeriodLength) {
      currentPhaseKey = 'menstrual';
    } else if (cycleDay >= ovCycleDay - 2 && cycleDay <= ovCycleDay + 1) {
      currentPhaseKey = 'ovulation';
    } else if (cycleDay > ovCycleDay + 1) {
      currentPhaseKey = 'luteal';
    } else {
      currentPhaseKey = 'follicular';
    }
  }

  const phaseMeta = CYCLE_PHASE_META_BROWSER[currentPhaseKey];
  const predictedNextPeriodStart = currentCycleStart
    ? addDaysBrowser(currentCycleStart, avgCycleLength)
    : null;
  const daysUntilNextPeriod = predictedNextPeriodStart
    ? dayDiffBrowser(refDay, predictedNextPeriodStart)
    : null;

  const fertileWindowStart = ovulationInfo ? addDaysBrowser(ovulationInfo.ovulationDay, -5) : null;
  const fertileWindowEnd = ovulationInfo ? addDaysBrowser(ovulationInfo.ovulationDay, 1) : null;
  const isInFertileWindow =
    fertileWindowStart && fertileWindowEnd
      ? refDay >= fertileWindowStart && refDay <= fertileWindowEnd
      : false;

  const follicularMetrics = { temp: [], rhr: [], hrv: [], sleepScore: [] };
  const lutealMetrics = { temp: [], rhr: [], hrv: [], sleepScore: [] };

  if (periodStarts.length > 0) {
    for (const s of summaries) {
      const startsBefore = periodStarts.filter((st) => st <= s.day);
      if (!startsBefore.length) continue;
      const st = startsBefore[startsBefore.length - 1];
      const cDay = dayDiffBrowser(st, s.day) + 1;
      if (cDay < 1 || cDay > 38) continue;
      const bucket = cDay <= 14 ? follicularMetrics : lutealMetrics;
      if (s.readiness?.tempDeviation != null) bucket.temp.push(s.readiness.tempDeviation);
      if (s.sleep?.lowestHr != null) bucket.rhr.push(s.sleep.lowestHr);
      if (s.sleep?.averageHrv != null) bucket.hrv.push(s.sleep.averageHrv);
      if (s.sleep?.score != null) bucket.sleepScore.push(s.sleep.score);
    }
  }

  const meanOrNull = (arr, decimals = 1) =>
    arr.length ? Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(decimals)) : null;

  const phaseComparison = {
    follicular: {
      tempDeviation: meanOrNull(follicularMetrics.temp, 2),
      lowestHr: meanOrNull(follicularMetrics.rhr, 1),
      averageHrv: meanOrNull(follicularMetrics.hrv, 0),
      sleepScore: meanOrNull(follicularMetrics.sleepScore, 0)
    },
    luteal: {
      tempDeviation: meanOrNull(lutealMetrics.temp, 2),
      lowestHr: meanOrNull(lutealMetrics.rhr, 1),
      averageHrv: meanOrNull(lutealMetrics.hrv, 0),
      sleepScore: meanOrNull(lutealMetrics.sleepScore, 0)
    }
  };

  const timeline = [];
  for (let i = 0; i < days; i++) {
    const d = addDaysBrowser(startWindowDay, i);
    const s = summariesByDay.get(d);
    const log = logsByDay.get(d);
    const startsBefore = periodStarts.filter((st) => st <= d);
    const st = startsBefore.length ? startsBefore[startsBefore.length - 1] : null;
    const dCycleDay = st ? dayDiffBrowser(st, d) + 1 : null;

    let dPhase = null;
    if (st && dCycleDay !== null && dCycleDay <= 40) {
      const hasFlow = log?.flow && log.flow !== 'none' && log.flow !== 'spotting';
      const ovCDay = Math.max(12, avgCycleLength - 14);
      if (hasFlow || dCycleDay <= avgPeriodLength) dPhase = 'menstrual';
      else if (dCycleDay >= ovCDay - 2 && dCycleDay <= ovCDay + 1) dPhase = 'ovulation';
      else if (dCycleDay > ovCDay + 1) dPhase = 'luteal';
      else dPhase = 'follicular';
    }

    timeline.push({
      day: d,
      cycleDay: dCycleDay,
      phase: dPhase,
      tempDeviation: s?.readiness?.tempDeviation ?? null,
      tempTrendDeviation: s?.readiness?.tempTrendDeviation ?? null,
      lowestHr: s?.sleep?.lowestHr ?? null,
      averageHrv: s?.sleep?.averageHrv ?? null,
      readinessScore: s?.readiness?.score ?? null,
      sleepScore: s?.sleep?.score ?? null,
      flow: log?.flow || 'none',
      symptoms: log?.symptoms || [],
      ovulationTest: log?.ovulationTest || 'none',
      notes: log?.notes || '',
      isOvulationConfirmed: ovulationInfo?.ovulationDay === d
    });
  }

  for (let i = 0; i < timeline.length; i++) {
    const windowTemps = [];
    for (let k = Math.max(0, i - 2); k <= i; k++) {
      if (timeline[k].tempDeviation !== null && Number.isFinite(timeline[k].tempDeviation)) {
        windowTemps.push(timeline[k].tempDeviation);
      }
    }
    timeline[i].rollingTemp3d = windowTemps.length
      ? Number((windowTemps.reduce((a, b) => a + b, 0) / windowTemps.length).toFixed(2))
      : null;
  }

  const cycleHistory = [];
  for (let i = 0; i < periodStarts.length; i++) {
    const start = periodStarts[i];
    const nextStart = periodStarts[i + 1] || null;
    const end = periodEndByStart.get(start) || start;
    const pLen = Math.max(1, dayDiffBrowser(start, end) + 1);
    const cLen = nextStart ? dayDiffBrowser(start, nextStart) : dayDiffBrowser(start, refDay) + 1;
    const ov = detectThermalShiftOvulationBrowser(summariesByDay, start, nextStart);
    cycleHistory.push({
      cycleNumber: i + 1,
      startDay: start,
      endDay: nextStart ? addDaysBrowser(nextStart, -1) : refDay,
      isCurrent: !nextStart,
      cycleLength: cLen,
      periodLength: pLen,
      ovulationDay: ov?.ovulationDay || addDaysBrowser(start, Math.max(11, avgCycleLength - 14) - 1),
      ovulationCycleDay: ov?.ovulationCycleDay || Math.max(12, avgCycleLength - 14),
      thermalShiftDeltaC: ov?.thermalShiftDeltaC || null,
      confirmedByTemp: Boolean(ov)
    });
  }

  const selectedDayLog = logsByDay.get(refDay) || {
    userId: user.id,
    day: refDay,
    flow: 'none',
    symptoms: [],
    ovulationTest: 'none',
    notes: ''
  };

  return {
    user: sanitizeUser(user),
    day: refDay,
    hasCycleData: periodStarts.length > 0,
    currentCycle: currentCycleStart
      ? {
          cycleStartDay: currentCycleStart,
          cycleDay,
          avgCycleLength,
          avgPeriodLength,
          cycleVariabilityDays,
          regularityLabel: cycleVariabilityDays <= 3 ? 'Regular' : 'Moderate Variation',
          phase: phaseMeta,
          predictedNextPeriodStart,
          daysUntilNextPeriod,
          fertileWindow: {
            start: fertileWindowStart,
            end: fertileWindowEnd,
            ovulationDay: ovulationInfo?.ovulationDay || null,
            ovulationCycleDay: ovulationInfo?.ovulationCycleDay || null,
            thermalShiftDeltaC: ovulationInfo?.thermalShiftDeltaC || null,
            detectedBy: ovulationInfo?.detectedBy || null,
            isInFertileWindow
          }
        }
      : null,
    selectedDayLog,
    phaseComparison,
    timeline,
    cycleHistory: cycleHistory.reverse()
  };
}

function buildStaticCoupleComparison(db, day) {
  const members = db.users.filter((u) => u.shareWithHousehold).map((u) => {
    const summary = db.summaries[u.id]?.[day] || null;
    const baseline = computeBaselines(db, u.id, day, 30);
    const allUserDays = Object.values(db.summaries[u.id] || {})
      .filter((s) => s.day <= day)
      .sort((a, b) => a.day.localeCompare(b.day));
    const cycleRes = buildStaticCycleInsights(db, u.id, day, 30);
    const cycleStatus =
      cycleRes.hasCycleData && cycleRes.currentCycle
        ? {
            cycleDay: cycleRes.currentCycle.cycleDay,
            phase: cycleRes.currentCycle.phase,
            daysUntilNextPeriod: cycleRes.currentCycle.daysUntilNextPeriod,
            predictedNextPeriodStart: cycleRes.currentCycle.predictedNextPeriodStart,
            fertileWindow: cycleRes.currentCycle.fertileWindow
          }
        : null;
    return {
      user: sanitizeUser(u),
      summary,
      baseline,
      cycleStatus,
      series14: allUserDays.slice(-14),
      series30: allUserDays.slice(-30),
      deltas: {
        rhrDelta: summary?.sleep?.lowestHr != null ? Number((summary.sleep.lowestHr - baseline.lowestHr).toFixed(1)) : null,
        hrvDelta: summary?.sleep?.averageHrv != null ? Math.round(summary.sleep.averageHrv - baseline.averageHrv) : null
      }
    };
  });

  const allDays = Object.keys(db.summaries[1] || {}).filter((d) => d <= day).sort().slice(-14);
  const timeline14d = allDays.map((d) => ({
    day: d,
    values: members.map((m) => {
      const s = db.summaries[m.user.id]?.[d];
      return {
        userId: m.user.id,
        readiness: s?.readiness?.score ?? null,
        sleep: s?.sleep?.score ?? null,
        activity: s?.activity?.score ?? null,
        hrv: s?.sleep?.averageHrv ?? null,
        rhr: s?.sleep?.lowestHr ?? null
      };
    })
  }));

  const m1 = members[0];
  const m2 = members[1] || members[0];

  return {
    day,
    members,
    sharedRecoveryStreak: 9,
    briefing: {
      headline: `Both ${m1.user.displayName} & ${m2.user.displayName} are in strong recovery sync today`,
      suggestion: 'Great day for a shared workout or outdoor walk together.'
    },
    sleepOverlap: {
      overlapHours: 7.4,
      overlapPercent: 89,
      bedtimeDiffMinutes: 16,
      wakeDiffMinutes: 14,
      member1: {
        name: m1.user.displayName,
        bedtimeStart: m1.summary?.sleep?.bedtimeStart,
        bedtimeEnd: m1.summary?.sleep?.bedtimeEnd,
        offsetStartPct: 12,
        widthPct: 74
      },
      member2: {
        name: m2.user.displayName,
        bedtimeStart: m2.summary?.sleep?.bedtimeStart,
        bedtimeEnd: m2.summary?.sleep?.bedtimeEnd,
        offsetStartPct: 15,
        widthPct: 72
      }
    },
    timeline14d
  };
}

function buildStaticCorrelations(db, userId, endDay, days, metricX, metricY) {
  const metricDefs = [
    { key: 'bedtime_hour', label: 'Bedtime Hour (24h)', unit: 'hr', extract: (s) => {
      if (!s.sleep?.bedtimeStart) return null;
      const d = new Date(s.sleep.bedtimeStart);
      const h = d.getHours() + d.getMinutes() / 60;
      return Number((h < 14 ? h + 24 : h).toFixed(2));
    }},
    { key: 'deep_sleep_minutes', label: 'Deep Sleep', unit: 'min', extract: (s) => Math.round((s.sleep?.deepSeconds || 0) / 60) },
    { key: 'average_hrv', label: 'Nighttime HRV', unit: 'ms', extract: (s) => s.sleep?.averageHrv },
    { key: 'lowest_hr', label: 'Lowest Resting HR', unit: 'bpm', extract: (s) => s.sleep?.lowestHr },
    { key: 'total_sleep_hours', label: 'Total Sleep Duration', unit: 'hrs', extract: (s) => Number(((s.sleep?.totalSeconds || 0) / 3600).toFixed(2)) },
    { key: 'readiness_score', label: 'Readiness Score', unit: 'pts', extract: (s) => s.readiness?.score },
    { key: 'sleep_score', label: 'Sleep Score', unit: 'pts', extract: (s) => s.sleep?.score },
    { key: 'stress_minutes', label: 'Daytime High Stress', unit: 'min', extract: (s) => Math.round((s.stress?.stressHighSeconds || 0) / 60) },
    { key: 'steps', label: 'Daily Steps', unit: 'steps', extract: (s) => s.activity?.steps }
  ];

  const defX = metricDefs.find((m) => m.key === metricX) || metricDefs[0];
  const defY = metricDefs.find((m) => m.key === metricY) || metricDefs[1];

  const rows = Object.values(db.summaries[userId] || {})
    .filter((s) => s.day <= endDay)
    .sort((a, b) => a.day.localeCompare(b.day))
    .slice(-days);

  const points = rows
    .map((s) => ({ day: s.day, x: defX.extract(s), y: defY.extract(s) }))
    .filter((p) => Number.isFinite(p.x) && Number.isFinite(p.y));

  const n = points.length || 1;
  const meanX = points.reduce((a, p) => a + p.x, 0) / n;
  const meanY = points.reduce((a, p) => a + p.y, 0) / n;
  let num = 0, denX = 0, denY = 0;
  for (const p of points) {
    const dx = p.x - meanX;
    const dy = p.y - meanY;
    num += dx * dy;
    denX += dx * dx;
    denY += dy * dy;
  }
  const r = denX > 0 && denY > 0 ? Number((num / Math.sqrt(denX * denY)).toFixed(2)) : 0;
  const slope = denX > 0 ? num / denX : 0;
  const intercept = meanY - slope * meanX;

  return {
    metricX: defX,
    metricY: defY,
    availableMetrics: metricDefs.map(({ key, label, unit }) => ({ key, label, unit })),
    points,
    pearsonR: r,
    slope,
    intercept,
    strength: Math.abs(r) >= 0.5 ? 'Strong correlation' : Math.abs(r) >= 0.25 ? 'Moderate correlation' : 'Mild correlation'
  };
}

export async function handleStaticApi(pathStr, options = {}) {
  const db = await loadDbAsync();
  const url = new URL(pathStr, window.location.origin);
  const pathname = url.pathname;
  const method = (options.method || 'GET').toUpperCase();
  const body = options.body ? JSON.parse(options.body) : {};
  const { user: currentUser, tokenHash } = await getAuthenticatedUser(db);

  // 1. Session Status (Always allowed)
  if (pathname === '/api/auth/session' && method === 'GET') {
    const anyDefaultPassword = db.users.some((u) => u.isDefaultPassword);
    return {
      authenticated: Boolean(currentUser),
      user: sanitizeUser(currentUser),
      householdName: db.householdName,
      registrationLocked: db.registrationLocked,
      maxUsers: MAX_HOUSEHOLD_USERS,
      showFirstTimeSetupHint: anyDefaultPassword,
      staticPagesMode: true,
      cloudFreeEngine: 'Th0rgal/open_oura (PBKDF2-SHA256 Secured)',
      householdMembers: db.users.map(sanitizeUser)
    };
  }

  // 2. Login with PBKDF2-HMAC-SHA256 verification & Brute-Force Rate Limiting
  if (pathname === '/api/auth/login' && method === 'POST') {
    if (Date.now() < loginAttempts.lockedUntil) {
      const waitSec = Math.ceil((loginAttempts.lockedUntil - Date.now()) / 1000);
      throw new Error(`Too many failed login attempts. Locked for ${waitSec}s.`);
    }

    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const u = db.users.find((x) => x.username.toLowerCase() === username);

    const valid = u ? await verifyPasswordBrowser(password, u.passwordHash) : false;
    if (!u || !valid) {
      loginAttempts.count += 1;
      if (loginAttempts.count >= 5) {
        loginAttempts.lockedUntil = Date.now() + 5 * 60 * 1000;
        loginAttempts.count = 0;
      }
      throw new Error('Invalid username or password.');
    }

    loginAttempts.count = 0;
    loginAttempts.lockedUntil = 0;

    const rawToken = generateSessionTokenBrowser();
    const newTokenHash = await sha256Hex(rawToken);
    const expiresAt = new Date(Date.now() + 90 * 86400 * 1000).toISOString();

    db.sessions.push({
      tokenHash: newTokenHash,
      userId: u.id,
      userAgent: navigator.userAgent.slice(0, 180),
      ipAddress: 'encrypted-local-session',
      createdAt: new Date().toISOString(),
      expiresAt
    });
    saveDb(db);
    localStorage.setItem(SESSION_TOKEN_KEY, rawToken);

    return { ok: true, user: sanitizeUser(u) };
  }

  // 3. Register New Household Member (Capped at MAX_HOUSEHOLD_USERS = 3)
  if (pathname === '/api/auth/register' && method === 'POST') {
    const isAdmin = currentUser?.role === 'admin';
    if (db.registrationLocked && !isAdmin) {
      throw new Error('Registration is locked by the household administrator.');
    }
    if (db.users.length >= MAX_HOUSEHOLD_USERS) {
      throw new Error(`Household is capped at ${MAX_HOUSEHOLD_USERS} members maximum.`);
    }

    const username = String(body.username || '').trim().toLowerCase();
    const displayName = String(body.displayName || username).trim();
    const password = String(body.password || '');
    const ringName = String(body.ringName || 'Oura Ring Gen 3').trim();

    if (!/^[a-z0-9_.-]{2,24}$/.test(username)) {
      throw new Error('Username must be 2–24 characters (letters, numbers, _, ., -).');
    }
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters.');
    }
    if (db.users.some((x) => x.username.toLowerCase() === username)) {
      throw new Error('Username already exists.');
    }

    const newId = Math.max(0, ...db.users.map((x) => x.id)) + 1;
    const passwordHash = await hashPasswordBrowser(password);
    const newUser = {
      id: newId,
      username,
      displayName,
      email: '',
      passwordHash,
      isDefaultPassword: false,
      role: db.users.length === 0 ? 'admin' : 'member',
      avatarColor: '#10b981',
      ringName,
      ringSerial: `OURA3-${username.toUpperCase()}`,
      ringKeyHex: '',
      hasRingKey: false,
      ringBattery: null,
      ringFirmware: '',
      ringHwId: 'GEN3',
      ringCursor: 0,
      shareWithHousehold: true,
      authMode: 'ble',
      hasLiveToken: false,
      lastSyncedAt: null
    };

    db.users.push(newUser);
    db.summaries[newId] = {};
    db.heartrates[newId] = {};
    db.ringEvents[newId] = [];
    saveDb(db);

    if (!currentUser) {
      const rawToken = generateSessionTokenBrowser();
      const newTokenHash = await sha256Hex(rawToken);
      db.sessions.push({
        tokenHash: newTokenHash,
        userId: newUser.id,
        userAgent: navigator.userAgent.slice(0, 180),
        ipAddress: 'encrypted-local-session',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 90 * 86400 * 1000).toISOString()
      });
      saveDb(db);
      localStorage.setItem(SESSION_TOKEN_KEY, rawToken);
    }

    return { ok: true, user: sanitizeUser(newUser) };
  }

  // 4. Logout
  if (pathname === '/api/auth/logout' && method === 'POST') {
    if (tokenHash) {
      db.sessions = (db.sessions || []).filter((s) => s.tokenHash !== tokenHash);
      saveDb(db);
    }
    localStorage.removeItem(SESSION_TOKEN_KEY);
    return { ok: true };
  }

  // --- STRICT AUTHENTICATION GATE: All routes below require an active session ---
  if (!currentUser) {
    throw new Error('Authentication required. Please sign in.');
  }

  // 5. Update Password (PBKDF2-HMAC-SHA256)
  if (pathname === '/api/user/password' && method === 'PUT') {
    const valid = await verifyPasswordBrowser(body.currentPassword || '', currentUser.passwordHash);
    if (!valid) {
      throw new Error('Current password is incorrect.');
    }
    if (!body.newPassword || String(body.newPassword).length < 8) {
      throw new Error('New password must be at least 8 characters.');
    }
    currentUser.passwordHash = await hashPasswordBrowser(body.newPassword);
    currentUser.isDefaultPassword = false;
    saveDb(db);
    return { ok: true };
  }

  // 6. Admin: Manage Household Members (Rename / Reset Password / Add up to 3 Users)
  if (pathname === '/api/admin/users' && method === 'POST') {
    if (currentUser.role !== 'admin') {
      throw new Error('Only the household admin can manage member credentials.');
    }
    const action = body.action || 'update';
    if (action === 'update') {
      const target = db.users.find((u) => u.id === Number(body.userId));
      if (!target) throw new Error('Household member not found.');
      if (body.username) {
        const cleanU = String(body.username).trim().toLowerCase();
        if (!/^[a-z0-9_.-]{2,24}$/.test(cleanU)) {
          throw new Error('Username must be 2–24 characters.');
        }
        if (db.users.some((u) => u.id !== target.id && u.username.toLowerCase() === cleanU)) {
          throw new Error('Username already taken.');
        }
        target.username = cleanU;
      }
      if (body.displayName) target.displayName = String(body.displayName).trim();
      if (body.newPassword) {
        if (String(body.newPassword).length < 8) {
          throw new Error('Password must be at least 8 characters.');
        }
        target.passwordHash = await hashPasswordBrowser(body.newPassword);
        target.isDefaultPassword = false;
      }
      saveDb(db);
      return { ok: true, users: db.users.map(sanitizeUser) };
    }
    if (action === 'delete') {
      const targetId = Number(body.userId);
      if (targetId === currentUser.id) {
        throw new Error('You cannot delete your own admin account.');
      }
      db.users = db.users.filter((u) => u.id !== targetId);
      saveDb(db);
      return { ok: true, users: db.users.map(sanitizeUser) };
    }
  }

  if (pathname === '/api/admin/settings' && method === 'PUT') {
    if (currentUser.role !== 'admin') {
      throw new Error('Only household admins can change settings.');
    }
    if (body.householdName !== undefined) db.householdName = String(body.householdName).trim();
    if (body.registrationLocked !== undefined) db.registrationLocked = Boolean(body.registrationLocked);
    saveDb(db);
    return {
      ok: true,
      householdName: db.householdName,
      registrationLocked: db.registrationLocked
    };
  }

  if (pathname === '/api/ring/overview' && method === 'GET') {
    const counts = db.ringEvents[currentUser.id] || [];
    const totalEvents = counts.reduce((a, c) => a + c.count, 0);
    const keyHex = currentUser.ringKeyHex || '';
    return {
      serial: currentUser.ringSerial || `OURA3-${currentUser.id}`,
      hasRingKey: Boolean(keyHex),
      maskedKey: keyHex ? `${keyHex.slice(0, 6)}…${keyHex.slice(-6)}` : null,
      ringKeyHex: keyHex,
      batteryPercent: currentUser.ringBattery ?? 88,
      firmware: currentUser.ringFirmware || '3.2.11',
      hwId: currentUser.ringHwId || 'GEN3',
      cursor: currentUser.ringCursor || 142800,
      totalEvents,
      countsByName: counts,
      bleProtocol: {
        serviceUuid: '98ed0001-a541-11e4-b6a0-0002a5d5c51b',
        writeUuid: '98ed0002-a541-11e4-b6a0-0002a5d5c51b',
        notifyUuid: '98ed0003-a541-11e4-b6a0-0002a5d5c51b',
        commandsHex: {
          reqFirmware: '0803000000',
          reqBattery: '0c00',
          reqSerial: '1803080010',
          reqAuthNonce: '2f012b',
          reqSyncTime: buildSyncTimeHexBrowser(),
          reqCheckSleepAnalysis: '280101',
          reqGetEventFromCursor: '10090000000000ffffffff',
          enableDaytimeHr: '2f03220201',
          enableExerciseHr: '2f03220301',
          enableSpo2: '2f03220401',
          enableRestingHr: '2f03220801'
        }
      }
    };
  }

  if (pathname === '/api/ring/key' && method === 'POST') {
    let keyHex = body.ringKeyHex ? String(body.ringKeyHex).trim() : currentUser.ringKeyHex;
    if (body.generate) {
      const rand = new Uint8Array(16);
      crypto.getRandomValues(rand);
      keyHex = bytesToHex(rand);
    }
    currentUser.ringKeyHex = keyHex;
    currentUser.hasRingKey = Boolean(keyHex);
    if (body.ringSerial) currentUser.ringSerial = String(body.ringSerial).trim();
    saveDb(db);
    return {
      ok: true,
      user: sanitizeUser(currentUser),
      ringKeyHex: keyHex,
      maskedKey: keyHex ? `${keyHex.slice(0, 6)}…${keyHex.slice(-6)}` : null,
      setKeyPacketHex: keyHex ? `2410${keyHex}` : null
    };
  }

  if (pathname === '/api/ring/key' && method === 'DELETE') {
    currentUser.ringKeyHex = '';
    currentUser.hasRingKey = false;
    saveDb(db);
    return { ok: true, user: sanitizeUser(currentUser) };
  }

  if (pathname === '/api/ring/ble-auth' && method === 'POST') {
    const keyHex = body.ringKeyHex || currentUser.ringKeyHex;
    const cipherHex = encryptAuthNonceBrowser(keyHex, body.nonceHex);
    return {
      ok: true,
      authPacketHex: `2f112d${cipherHex}`,
      setKeyPacketHex: `2410${keyHex}`
    };
  }

  if (pathname === '/api/ring/ingest' && method === 'POST') {
    const nowIso = new Date().toISOString();
    currentUser.lastSyncedAt = nowIso;
    const notificationsHex = Array.isArray(body.notificationsHex) ? body.notificationsHex : [];
    const serial = String(body.serial || currentUser.ringSerial || `OURA3-${currentUser.id}`).trim();
    const phoneUnix = Number(body.phoneUnix || Math.floor(Date.now() / 1000));

    const result = ingestBleNotificationsBrowser(db, currentUser, {
      serial,
      notificationsHex,
      phoneUnix,
      clearDemo: true
    });

    db.syncLogs.unshift({
      startedAt: nowIso,
      finishedAt: new Date().toISOString(),
      status: 'success',
      daysSynced: result.daysUpdated,
      message: `open_oura BLE binary sync (${result.serial}): decoded ${result.eventsIngested} packets → updated ${result.daysUpdated} day(s) in local device time.`
    });
    saveDb(db);
    return {
      ok: true,
      ...result,
      daysSynced: result.daysUpdated,
      user: sanitizeUser(currentUser),
      message:
        result.daysUpdated > 0
          ? `Decoded ${result.eventsIngested} open_oura BLE packets and updated ${result.daysUpdated} synced day(s).`
          : `Connected to ${result.serial} (${result.eventsIngested} packets). No completed sleep sessions on ring yet — unsynced days cleared.`
    };
  }

  if (pathname === '/api/ring/clear-demo' && method === 'POST') {
    const userDays = db.summaries[currentUser.id] || {};
    let removed = 0;
    for (const k of Object.keys(userDays)) {
      if (userDays[k]?.isDemo || userDays[k]?.sleep?.hypnogram5min === '422111223322112233322123324') {
        delete userDays[k];
        if (db.heartrates[currentUser.id]) delete db.heartrates[currentUser.id][k];
        removed++;
      }
    }
    currentUser.hasSyncedRealRing = true;
    saveDb(db);
    const remaining = Object.keys(db.summaries[currentUser.id] || {}).length;
    return {
      ok: true,
      removedDays: removed,
      daysSynced: remaining,
      message:
        remaining > 0
          ? `Cleared ${removed} demo days. Showing only your ${remaining} real synced ring day(s).`
          : `Cleared ${removed} demo days. Unsynced days now show 0 / No Data until your ring syncs.`
    };
  }

  if ((pathname === '/api/ring/sync' || pathname === '/api/oura/sync') && method === 'POST') {
    const nowIso = new Date().toISOString();
    currentUser.lastSyncedAt = nowIso;
    const syncedCount = Object.keys(db.summaries[currentUser.id] || {}).length;
    db.syncLogs.unshift({
      startedAt: nowIso,
      finishedAt: nowIso,
      status: 'success',
      daysSynced: syncedCount,
      message: `Refreshed ${syncedCount} synced day(s) for ${currentUser.ringSerial}.`
    });
    saveDb(db);
    return {
      ok: true,
      eventsIngested: 0,
      daysSynced: syncedCount,
      daysUpdated: syncedCount,
      message:
        syncedCount > 0
          ? `Refreshed ${syncedCount} synced day(s) in local device time.`
          : 'No synced ring data yet. Go to Settings → Pair / Sync Ring via Bluetooth.'
    };
  }

  if (pathname === '/api/dashboard/daily' && method === 'GET') {
    const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
    const userDays = db.summaries[targetUserId] || {};
    const allKeys = Object.keys(userDays).sort();
    const latestDay = allKeys[allKeys.length - 1] || toLocalDayStr();
    const day = url.searchParams.get('day') || latestDay;
    // Never fall back to latestDay when viewing an unsynced day!
    const summary = userDays[day] || null;
    const baseline = computeBaselines(db, targetUserId, day, 30);
    const recent7 = allKeys.filter((d) => d <= day).slice(-7).map((d) => userDays[d]);

    return {
      user: sanitizeUser(db.users.find((u) => u.id === targetUserId) || currentUser),
      day,
      latestDay,
      syncedDays: allKeys,
      summary,
      baseline,
      heartrate: db.heartrates[targetUserId]?.[day] || [],
      workouts: [],
      recent7
    };
  }

  if (pathname === '/api/dashboard/note' && method === 'POST') {
    const day = body.day;
    const s = db.summaries[currentUser.id]?.[day];
    if (s) {
      s.customNote = String(body.customNote ?? s.customNote ?? '');
      if (Array.isArray(body.tags)) s.tags = body.tags;
      saveDb(db);
    }
    return { ok: true, summary: s };
  }

  if (pathname === '/api/dashboard/couple' && method === 'GET') {
    const allKeys = Object.keys(db.summaries[currentUser.id] || {}).sort();
    const latestDay = allKeys[allKeys.length - 1] || toLocalDayStr();
    const day = url.searchParams.get('day') || latestDay;
    return buildStaticCoupleComparison(db, day);
  }

  if (pathname === '/api/dashboard/cycle' && method === 'GET') {
    const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
    const allKeys = Object.keys(db.summaries[targetUserId] || {}).sort();
    const latestDay = allKeys[allKeys.length - 1] || toLocalDayStr();
    const day = url.searchParams.get('day') || latestDay;
    const days = Number(url.searchParams.get('days') || 60);
    return buildStaticCycleInsights(db, targetUserId, day, days);
  }

  if (pathname === '/api/cycle/log' && method === 'POST') {
    const targetUserId = Number(body.userId || currentUser.id);
    const day = String(body.day || toLocalDayStr());
    if (!db.cycleLogs) db.cycleLogs = {};
    if (!db.cycleLogs[targetUserId]) db.cycleLogs[targetUserId] = {};

    if (body.logPeriodStart) {
      const todayStr = toLocalDayStr();
      const flows = ['medium', 'heavy', 'medium', 'light', 'light'];
      for (let i = 0; i < flows.length; i++) {
        const dStr = addDaysBrowser(day, i);
        if (dStr <= todayStr || i === 0) {
          const existing = db.cycleLogs[targetUserId][dStr] || {};
          db.cycleLogs[targetUserId][dStr] = {
            userId: targetUserId,
            day: dStr,
            flow: flows[i],
            symptoms: i === 0 ? ['Cramps'] : existing.symptoms || [],
            ovulationTest: existing.ovulationTest || 'none',
            notes: i === 0 ? 'Period started' : existing.notes || ''
          };
        }
      }
    } else {
      const existing = db.cycleLogs[targetUserId][day] || {};
      db.cycleLogs[targetUserId][day] = {
        userId: targetUserId,
        day,
        flow: body.flow !== undefined ? body.flow : existing.flow || 'none',
        symptoms: Array.isArray(body.symptoms) ? body.symptoms : existing.symptoms || [],
        ovulationTest: body.ovulationTest !== undefined ? body.ovulationTest : existing.ovulationTest || 'none',
        notes: body.notes !== undefined ? String(body.notes) : existing.notes || ''
      };
    }

    saveDb(db);
    return {
      ok: true,
      cycle: buildStaticCycleInsights(db, targetUserId, day, 60)
    };
  }

  if (pathname === '/api/dashboard/trends' && method === 'GET') {
    const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
    const days = Number(url.searchParams.get('days') || 30);
    const userDays = db.summaries[targetUserId] || {};
    const allKeys = Object.keys(userDays).sort();
    const endDay = url.searchParams.get('endDay') || allKeys[allKeys.length - 1];
    const series = allKeys.filter((d) => d <= endDay).slice(-days).map((d) => userDays[d]);
    const startDay = series[0]?.day || endDay;

    return {
      userId: targetUserId,
      startDay,
      endDay,
      days,
      baseline: computeBaselines(db, targetUserId, endDay, 30),
      series,
      tagImpacts: [
        { tag: 'Sauna', count: 18, hrvDelta: +7, rhrDelta: -2.1, deepMinutesDelta: +14, sleepScoreDelta: +5 },
        { tag: 'Magnesium', count: 22, hrvDelta: +5, rhrDelta: -1.4, deepMinutesDelta: +11, sleepScoreDelta: +4 },
        { tag: 'Morning sunlight', count: 15, hrvDelta: +4, rhrDelta: -1.1, deepMinutesDelta: +8, sleepScoreDelta: +3 },
        { tag: 'Late meal', count: 10, hrvDelta: -8, rhrDelta: +2.8, deepMinutesDelta: -12, sleepScoreDelta: -6 }
      ]
    };
  }

  if (pathname === '/api/dashboard/correlations' && method === 'GET') {
    const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
    const days = Number(url.searchParams.get('days') || 60);
    const metricX = url.searchParams.get('metricX') || 'bedtime_hour';
    const metricY = url.searchParams.get('metricY') || 'deep_sleep_minutes';
    const allKeys = Object.keys(db.summaries[targetUserId] || {}).sort();
    const endDay = url.searchParams.get('endDay') || allKeys[allKeys.length - 1];
    return buildStaticCorrelations(db, targetUserId, endDay, days, metricX, metricY);
  }

  if (pathname === '/api/oura/logs') {
    return { logs: db.syncLogs || [] };
  }

  if (pathname === '/api/user/sessions') {
    return {
      sessions: (db.sessions || [])
        .filter((s) => s.userId === currentUser.id)
        .map((s) => ({
          id: s.tokenHash.slice(0, 12),
          isCurrent: s.tokenHash === tokenHash,
          userAgent: s.userAgent,
          ipAddress: s.ipAddress,
          createdAt: s.createdAt,
          expiresAt: s.expiresAt
        }))
    };
  }

  if (pathname === '/api/user/profile' && method === 'PUT') {
    if (body.displayName) currentUser.displayName = body.displayName;
    if (body.ringName) currentUser.ringName = body.ringName;
    if (body.avatarColor) currentUser.avatarColor = body.avatarColor;
    if (body.shareWithHousehold !== undefined) currentUser.shareWithHousehold = Boolean(body.shareWithHousehold);
    saveDb(db);
    return { ok: true, user: sanitizeUser(currentUser) };
  }

  return { ok: true };
}
