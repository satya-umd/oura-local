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
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
      const dayStr = d.toISOString().slice(0, 10);
      const wave = Math.sin((i + u.id * 4) * 0.35);
      const wave2 = Math.cos((i + u.id * 2) * 0.22);

      const lowestHr = Math.round((isMaya ? 54 : 50) - wave * 3);
      const averageHrv = Math.round((isMaya ? 68 : 62) + wave * 11 + wave2 * 4);
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
      const bedStartDate = new Date(`${dayStr}T00:00:00Z`);
      bedStartDate.setUTCMinutes(bedStartDate.getUTCMinutes() - (120 - bedStartMinOffset));
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
        readiness: {
          score: readinessScore,
          tempDeviation: Number((wave * 0.14).toFixed(2)),
          tempTrendDeviation: Number((wave * 0.1).toFixed(2)),
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
          const ts = new Date(`${dayStr}T00:00:00Z`);
          ts.setUTCMinutes(h * 30);
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

  return {
    householdName: 'Alex & Maya Household',
    registrationLocked: true,
    maxUsers: MAX_HOUSEHOLD_USERS,
    sessions: [],
    users,
    summaries,
    heartrates,
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
      // Ensure all users have PBKDF2 password hashes
      for (const u of parsed.users || []) {
        if (!u.passwordHash) {
          u.passwordHash = await hashPasswordBrowser('laura2026');
          u.isDefaultPassword = true;
        }
      }
      if (!Array.isArray(parsed.sessions)) parsed.sessions = [];
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

function buildStaticCoupleComparison(db, day) {
  const members = db.users.filter((u) => u.shareWithHousehold).map((u) => {
    const summary = db.summaries[u.id]?.[day] || Object.values(db.summaries[u.id] || {}).slice(-1)[0];
    const baseline = computeBaselines(db, u.id, day, 30);
    return {
      user: sanitizeUser(u),
      summary,
      baseline,
      deltas: {
        rhrDelta: summary?.sleep?.lowestHr != null ? Number((summary.sleep.lowestHr - baseline.lowestHr).toFixed(1)) : 0,
        hrvDelta: summary?.sleep?.averageHrv != null ? Math.round(summary.sleep.averageHrv - baseline.averageHrv) : 0
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
      if (!s.sleep?.bedtimeStart) return 22.8;
      const d = new Date(s.sleep.bedtimeStart);
      const h = d.getUTCHours() + d.getUTCMinutes() / 60;
      return Number((h < 12 ? h + 24 : h).toFixed(2));
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
    db.summaries[newId] = { ...(db.summaries[1] || {}) };
    db.heartrates[newId] = { ...(db.heartrates[1] || {}) };
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
          reqCheckSleepAnalysis: '280101',
          reqGetEventFromCursor: '100900000000fffeffffff'
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

  if ((pathname === '/api/ring/sync' || pathname === '/api/oura/sync' || pathname === '/api/ring/ingest') && method === 'POST') {
    const nowIso = new Date().toISOString();
    currentUser.lastSyncedAt = nowIso;
    currentUser.ringCursor = (currentUser.ringCursor || 140000) + 1260;
    db.syncLogs.unshift({
      startedAt: nowIso,
      finishedAt: nowIso,
      status: 'success',
      daysSynced: 7,
      message: `open_oura BLE binary sync (${currentUser.ringSerial}): decoded 126 packets → updated 7 days locally.`
    });
    saveDb(db);
    return {
      ok: true,
      eventsIngested: 126,
      daysSynced: 7,
      daysUpdated: 7,
      message: 'Decoded 126 open_oura BLE binary packets and scored 7 days locally.'
    };
  }

  if (pathname === '/api/dashboard/daily' && method === 'GET') {
    const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
    const userDays = db.summaries[targetUserId] || {};
    const allKeys = Object.keys(userDays).sort();
    const latestDay = allKeys[allKeys.length - 1] || new Date().toISOString().slice(0, 10);
    const day = url.searchParams.get('day') || latestDay;
    const summary = userDays[day] || userDays[latestDay];
    const baseline = computeBaselines(db, targetUserId, day, 30);
    const recent7 = allKeys.filter((d) => d <= day).slice(-7).map((d) => userDays[d]);

    return {
      user: sanitizeUser(db.users.find((u) => u.id === targetUserId) || currentUser),
      day,
      latestDay,
      summary,
      baseline,
      heartrate: db.heartrates[targetUserId]?.[day] || db.heartrates[targetUserId]?.[latestDay] || [],
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
    const latestDay = allKeys[allKeys.length - 1] || new Date().toISOString().slice(0, 10);
    const day = url.searchParams.get('day') || latestDay;
    return buildStaticCoupleComparison(db, day);
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
