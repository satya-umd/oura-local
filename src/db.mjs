import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { encryptSecret, decryptSecret } from './security.mjs';

const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'laura.db');
export const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA synchronous = NORMAL;

  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    email TEXT DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    avatar_color TEXT NOT NULL DEFAULT '#6366f1',
    ring_name TEXT NOT NULL DEFAULT 'Oura Ring Gen 3',
    ring_size TEXT DEFAULT '',
    share_with_household INTEGER NOT NULL DEFAULT 1,
    auth_mode TEXT NOT NULL DEFAULT 'demo',
    encrypted_pat TEXT,
    encrypted_oauth_access TEXT,
    encrypted_oauth_refresh TEXT,
    oauth_expires_at INTEGER,
    oura_user_id TEXT,
    oura_email TEXT,
    last_synced_at TEXT,
    sync_status TEXT NOT NULL DEFAULT 'idle',
    sync_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    user_agent TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS daily_summaries (
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    readiness_score INTEGER,
    temp_deviation REAL,
    temp_trend_deviation REAL,
    hrv_balance_contrib INTEGER,
    resting_hr_contrib INTEGER,
    recovery_index_contrib INTEGER,
    sleep_balance_contrib INTEGER,
    previous_night_contrib INTEGER,
    activity_balance_contrib INTEGER,
    sleep_score INTEGER,
    total_sleep_seconds INTEGER,
    deep_sleep_seconds INTEGER,
    rem_sleep_seconds INTEGER,
    light_sleep_seconds INTEGER,
    awake_seconds INTEGER,
    time_in_bed_seconds INTEGER,
    sleep_efficiency INTEGER,
    sleep_latency_seconds INTEGER,
    lowest_hr INTEGER,
    average_hr REAL,
    average_hrv INTEGER,
    average_breath REAL,
    bedtime_start TEXT,
    bedtime_end TEXT,
    hypnogram_5min TEXT,
    hr_5min_json TEXT,
    hrv_5min_json TEXT,
    activity_score INTEGER,
    steps INTEGER,
    active_calories INTEGER,
    total_calories INTEGER,
    equivalent_walking_distance INTEGER,
    high_activity_seconds INTEGER,
    medium_activity_seconds INTEGER,
    low_activity_seconds INTEGER,
    sedentary_seconds INTEGER,
    inactivity_alerts INTEGER,
    spo2_percentage REAL,
    breathing_disturbance_index REAL,
    stress_high_seconds INTEGER,
    recovery_high_seconds INTEGER,
    stress_day_summary TEXT,
    tags_json TEXT DEFAULT '[]',
    custom_note TEXT DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, day),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_daily_summaries_day ON daily_summaries(day);

  CREATE TABLE IF NOT EXISTS heartrate_samples (
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    bpm INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'awake',
    PRIMARY KEY (user_id, timestamp),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_hr_user_day ON heartrate_samples(user_id, day);

  CREATE TABLE IF NOT EXISTS workouts (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    activity TEXT NOT NULL,
    calories INTEGER DEFAULT 0,
    distance REAL DEFAULT 0,
    start_datetime TEXT,
    end_datetime TEXT,
    intensity TEXT DEFAULT 'moderate',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_workouts_user_day ON workouts(user_id, day);

  CREATE TABLE IF NOT EXISTS sync_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    days_synced INTEGER DEFAULT 0,
    message TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Th0rgal/open_oura native cloud-free BLE tables
  CREATE TABLE IF NOT EXISTS ring_devices (
    serial TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    hw_id TEXT DEFAULT '',
    firmware TEXT DEFAULT '',
    bootloader TEXT DEFAULT '',
    battery_percent INTEGER,
    charging INTEGER DEFAULT 0,
    last_seen_unix INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ring_sync_state (
    serial TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    last_timestamp INTEGER NOT NULL DEFAULT 0,
    updated_unix INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ring_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    serial TEXT NOT NULL,
    tag INTEGER NOT NULL,
    name TEXT NOT NULL,
    ring_timestamp INTEGER NOT NULL,
    body BLOB NOT NULL,
    decoded_json TEXT,
    captured_unix INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_ring_events_user_ts
    ON ring_events(user_id, serial, ring_timestamp);
  CREATE INDEX IF NOT EXISTS idx_ring_events_tag
    ON ring_events(user_id, tag, ring_timestamp);

  CREATE TABLE IF NOT EXISTS ring_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    serial TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    captured_unix INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Safe migrations for existing `users` table
const userCols = new Set(
  db.prepare(`PRAGMA table_info(users)`).all().map((c) => c.name)
);
const addColIfMissing = (col, typeDef) => {
  if (!userCols.has(col)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${col} ${typeDef}`);
  }
};
addColIfMissing('ring_serial', "TEXT DEFAULT ''");
addColIfMissing('encrypted_ring_key', 'TEXT');
addColIfMissing('ring_battery', 'INTEGER');
addColIfMissing('ring_firmware', "TEXT DEFAULT ''");
addColIfMissing('ring_hw_id', "TEXT DEFAULT ''");
addColIfMissing('ring_cursor', 'INTEGER DEFAULT 0');

export function getSetting(key, defaultValue = null) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  if (!row) return defaultValue;
  try {
    return JSON.parse(row.value);
  } catch {
    return row.value;
  }
}

export function setSetting(key, value) {
  const serialized = JSON.stringify(value);
  db.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `).run(key, serialized);
}

export function sanitizeUser(row) {
  if (!row) return null;
  const hasRingKey = Boolean(row.encrypted_ring_key);
  const hasPat = Boolean(row.encrypted_pat);
  const hasOAuth = Boolean(row.encrypted_oauth_access);
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    email: row.email || '',
    role: row.role,
    avatarColor: row.avatar_color,
    ringName: row.ring_name,
    ringSize: row.ring_size || '',
    ringSerial: row.ring_serial || '',
    hasRingKey,
    ringBattery: row.ring_battery ?? null,
    ringFirmware: row.ring_firmware || '',
    ringHwId: row.ring_hw_id || '',
    ringCursor: row.ring_cursor || 0,
    shareWithHousehold: Boolean(row.share_with_household),
    authMode: hasRingKey ? 'ble' : hasOAuth ? 'oauth2' : hasPat ? 'pat' : row.auth_mode || 'demo',
    hasLiveToken: hasRingKey || hasPat || hasOAuth,
    ouraUserId: row.oura_user_id || null,
    ouraEmail: row.oura_email || null,
    lastSyncedAt: row.last_synced_at,
    syncStatus: row.sync_status,
    syncError: row.sync_error,
    createdAt: row.created_at
  };
}

export function getUserById(id) {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  return sanitizeUser(row);
}

export function getRawUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

export function getRawUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim());
}

export function listHouseholdUsers() {
  const rows = db.prepare('SELECT * FROM users ORDER BY id ASC').all();
  return rows.map(sanitizeUser);
}

export function createUser({
  username,
  displayName,
  email = '',
  passwordHash,
  role = 'member',
  avatarColor = '#6366f1',
  ringName = 'Oura Ring Gen 3',
  shareWithHousehold = 1,
  authMode = 'demo'
}) {
  const result = db.prepare(`
    INSERT INTO users (username, display_name, email, password_hash, role, avatar_color, ring_name, share_with_household, auth_mode)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    username.trim().toLowerCase(),
    displayName.trim(),
    email.trim(),
    passwordHash,
    role,
    avatarColor,
    ringName,
    shareWithHousehold ? 1 : 0,
    authMode
  );
  return getUserById(Number(result.lastInsertRowid));
}

export function updateUserProfile(userId, { displayName, email, avatarColor, ringName, shareWithHousehold }) {
  const current = getRawUserById(userId);
  if (!current) return null;
  db.prepare(`
    UPDATE users
    SET display_name = ?,
        email = ?,
        avatar_color = ?,
        ring_name = ?,
        share_with_household = ?
    WHERE id = ?
  `).run(
    displayName !== undefined ? String(displayName).trim() : current.display_name,
    email !== undefined ? String(email).trim() : current.email,
    avatarColor !== undefined ? String(avatarColor).trim() : current.avatar_color,
    ringName !== undefined ? String(ringName).trim() : current.ring_name,
    shareWithHousehold !== undefined ? (shareWithHousehold ? 1 : 0) : current.share_with_household,
    userId
  );
  return getUserById(userId);
}

export function updateUserPassword(userId, passwordHash) {
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, userId);
}

export function adminUpdateHouseholdUser(targetUserId, { username, displayName, passwordHash }) {
  const current = getRawUserById(targetUserId);
  if (!current) throw new Error('Household member not found.');
  const nextUsername = username ? String(username).trim().toLowerCase() : current.username;
  const nextDisplay = displayName ? String(displayName).trim() : current.display_name;
  const nextHash = passwordHash || current.password_hash;

  db.prepare(`
    UPDATE users
    SET username = ?,
        display_name = ?,
        password_hash = ?
    WHERE id = ?
  `).run(nextUsername, nextDisplay, nextHash, targetUserId);
  return listHouseholdUsers();
}

export function adminDeleteHouseholdUser(targetUserId) {
  db.prepare('DELETE FROM users WHERE id = ?').run(targetUserId);
  return listHouseholdUsers();
}

export function saveUserPat(userId, patToken, ouraProfile = {}) {
  const encrypted = encryptSecret(patToken);
  db.prepare(`
    UPDATE users
    SET encrypted_pat = ?,
        encrypted_oauth_access = NULL,
        encrypted_oauth_refresh = NULL,
        oauth_expires_at = NULL,
        auth_mode = 'pat',
        oura_user_id = COALESCE(?, oura_user_id),
        oura_email = COALESCE(?, oura_email),
        sync_error = NULL
    WHERE id = ?
  `).run(encrypted, ouraProfile.id || null, ouraProfile.email || null, userId);
  return getUserById(userId);
}

export function saveUserOAuthTokens(userId, { accessToken, refreshToken, expiresIn, ouraProfile = {} }) {
  const encAccess = encryptSecret(accessToken);
  const encRefresh = refreshToken ? encryptSecret(refreshToken) : null;
  const expiresAt = expiresIn ? Date.now() + Number(expiresIn) * 1000 : null;
  db.prepare(`
    UPDATE users
    SET encrypted_oauth_access = ?,
        encrypted_oauth_refresh = COALESCE(?, encrypted_oauth_refresh),
        oauth_expires_at = ?,
        encrypted_pat = NULL,
        auth_mode = 'oauth2',
        oura_user_id = COALESCE(?, oura_user_id),
        oura_email = COALESCE(?, oura_email),
        sync_error = NULL
    WHERE id = ?
  `).run(encAccess, encRefresh, expiresAt, ouraProfile.id || null, ouraProfile.email || null, userId);
  return getUserById(userId);
}

export function disconnectUserOura(userId) {
  db.prepare(`
    UPDATE users
    SET encrypted_pat = NULL,
        encrypted_oauth_access = NULL,
        encrypted_oauth_refresh = NULL,
        oauth_expires_at = NULL,
        auth_mode = 'demo',
        sync_status = 'idle',
        sync_error = NULL
    WHERE id = ?
  `).run(userId);
  return getUserById(userId);
}

export function getDecryptedUserCredentials(userId) {
  const row = getRawUserById(userId);
  if (!row) return null;
  if (row.encrypted_oauth_access) {
    return {
      mode: 'oauth2',
      accessToken: decryptSecret(row.encrypted_oauth_access),
      refreshToken: decryptSecret(row.encrypted_oauth_refresh),
      expiresAt: row.oauth_expires_at
    };
  }
  if (row.encrypted_pat) {
    return {
      mode: 'pat',
      accessToken: decryptSecret(row.encrypted_pat)
    };
  }
  return null;
}

export function createSession({ tokenHash, userId, userAgent = '', ipAddress = '', daysValid = 90 }) {
  const expiresAt = new Date(Date.now() + daysValid * 86400 * 1000).toISOString();
  db.prepare(`
    INSERT INTO sessions (token_hash, user_id, user_agent, ip_address, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(tokenHash, userId, String(userAgent).slice(0, 250), String(ipAddress).slice(0, 64), expiresAt);
  return expiresAt;
}

export function getSessionUser(tokenHash) {
  if (!tokenHash) return null;
  const row = db.prepare(`
    SELECT s.token_hash, s.expires_at, u.*
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(tokenHash);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  return sanitizeUser(row);
}

export function listUserSessions(userId, currentTokenHash = null) {
  const rows = db.prepare(`
    SELECT token_hash, user_agent, ip_address, created_at, expires_at
    FROM sessions
    WHERE user_id = ? AND expires_at > datetime('now')
    ORDER BY created_at DESC
  `).all(userId);
  return rows.map((r) => ({
    id: r.token_hash.slice(0, 12),
    isCurrent: r.token_hash === currentTokenHash,
    userAgent: r.user_agent,
    ipAddress: r.ip_address,
    createdAt: r.created_at,
    expiresAt: r.expires_at
  }));
}

export function deleteSession(tokenHash) {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
}

export function deleteSessionByPrefix(userId, prefix) {
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND substr(token_hash, 1, 12) = ?').run(userId, prefix);
}

export function upsertDailySummary(userId, day, data) {
  const existing = db.prepare('SELECT * FROM daily_summaries WHERE user_id = ? AND day = ?').get(userId, day) || {};
  const merged = { ...existing, ...data };

  db.prepare(`
    INSERT INTO daily_summaries (
      user_id, day,
      readiness_score, temp_deviation, temp_trend_deviation,
      hrv_balance_contrib, resting_hr_contrib, recovery_index_contrib,
      sleep_balance_contrib, previous_night_contrib, activity_balance_contrib,
      sleep_score, total_sleep_seconds, deep_sleep_seconds, rem_sleep_seconds,
      light_sleep_seconds, awake_seconds, time_in_bed_seconds, sleep_efficiency,
      sleep_latency_seconds, lowest_hr, average_hr, average_hrv, average_breath,
      bedtime_start, bedtime_end, hypnogram_5min, hr_5min_json, hrv_5min_json,
      activity_score, steps, active_calories, total_calories,
      equivalent_walking_distance, high_activity_seconds, medium_activity_seconds,
      low_activity_seconds, sedentary_seconds, inactivity_alerts,
      spo2_percentage, breathing_disturbance_index,
      stress_high_seconds, recovery_high_seconds, stress_day_summary,
      tags_json, custom_note, updated_at
    ) VALUES (
      ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, ?,
      ?, ?, ?,
      ?, ?, datetime('now')
    )
    ON CONFLICT(user_id, day) DO UPDATE SET
      readiness_score = excluded.readiness_score,
      temp_deviation = excluded.temp_deviation,
      temp_trend_deviation = excluded.temp_trend_deviation,
      hrv_balance_contrib = excluded.hrv_balance_contrib,
      resting_hr_contrib = excluded.resting_hr_contrib,
      recovery_index_contrib = excluded.recovery_index_contrib,
      sleep_balance_contrib = excluded.sleep_balance_contrib,
      previous_night_contrib = excluded.previous_night_contrib,
      activity_balance_contrib = excluded.activity_balance_contrib,
      sleep_score = excluded.sleep_score,
      total_sleep_seconds = excluded.total_sleep_seconds,
      deep_sleep_seconds = excluded.deep_sleep_seconds,
      rem_sleep_seconds = excluded.rem_sleep_seconds,
      light_sleep_seconds = excluded.light_sleep_seconds,
      awake_seconds = excluded.awake_seconds,
      time_in_bed_seconds = excluded.time_in_bed_seconds,
      sleep_efficiency = excluded.sleep_efficiency,
      sleep_latency_seconds = excluded.sleep_latency_seconds,
      lowest_hr = excluded.lowest_hr,
      average_hr = excluded.average_hr,
      average_hrv = excluded.average_hrv,
      average_breath = excluded.average_breath,
      bedtime_start = excluded.bedtime_start,
      bedtime_end = excluded.bedtime_end,
      hypnogram_5min = excluded.hypnogram_5min,
      hr_5min_json = excluded.hr_5min_json,
      hrv_5min_json = excluded.hrv_5min_json,
      activity_score = excluded.activity_score,
      steps = excluded.steps,
      active_calories = excluded.active_calories,
      total_calories = excluded.total_calories,
      equivalent_walking_distance = excluded.equivalent_walking_distance,
      high_activity_seconds = excluded.high_activity_seconds,
      medium_activity_seconds = excluded.medium_activity_seconds,
      low_activity_seconds = excluded.low_activity_seconds,
      sedentary_seconds = excluded.sedentary_seconds,
      inactivity_alerts = excluded.inactivity_alerts,
      spo2_percentage = excluded.spo2_percentage,
      breathing_disturbance_index = excluded.breathing_disturbance_index,
      stress_high_seconds = excluded.stress_high_seconds,
      recovery_high_seconds = excluded.recovery_high_seconds,
      stress_day_summary = excluded.stress_day_summary,
      tags_json = excluded.tags_json,
      custom_note = excluded.custom_note,
      updated_at = datetime('now')
  `).run(
    userId,
    day,
    merged.readiness_score ?? null,
    merged.temp_deviation ?? null,
    merged.temp_trend_deviation ?? null,
    merged.hrv_balance_contrib ?? null,
    merged.resting_hr_contrib ?? null,
    merged.recovery_index_contrib ?? null,
    merged.sleep_balance_contrib ?? null,
    merged.previous_night_contrib ?? null,
    merged.activity_balance_contrib ?? null,
    merged.sleep_score ?? null,
    merged.total_sleep_seconds ?? null,
    merged.deep_sleep_seconds ?? null,
    merged.rem_sleep_seconds ?? null,
    merged.light_sleep_seconds ?? null,
    merged.awake_seconds ?? null,
    merged.time_in_bed_seconds ?? null,
    merged.sleep_efficiency ?? null,
    merged.sleep_latency_seconds ?? null,
    merged.lowest_hr ?? null,
    merged.average_hr ?? null,
    merged.average_hrv ?? null,
    merged.average_breath ?? null,
    merged.bedtime_start ?? null,
    merged.bedtime_end ?? null,
    merged.hypnogram_5min ?? null,
    typeof merged.hr_5min_json === 'string' ? merged.hr_5min_json : JSON.stringify(merged.hr_5min_json || []),
    typeof merged.hrv_5min_json === 'string' ? merged.hrv_5min_json : JSON.stringify(merged.hrv_5min_json || []),
    merged.activity_score ?? null,
    merged.steps ?? null,
    merged.active_calories ?? null,
    merged.total_calories ?? null,
    merged.equivalent_walking_distance ?? null,
    merged.high_activity_seconds ?? null,
    merged.medium_activity_seconds ?? null,
    merged.low_activity_seconds ?? null,
    merged.sedentary_seconds ?? null,
    merged.inactivity_alerts ?? null,
    merged.spo2_percentage ?? null,
    merged.breathing_disturbance_index ?? null,
    merged.stress_high_seconds ?? null,
    merged.recovery_high_seconds ?? null,
    merged.stress_day_summary ?? null,
    typeof merged.tags_json === 'string' ? merged.tags_json : JSON.stringify(merged.tags_json || []),
    merged.custom_note ?? ''
  );
}

export function formatDailySummary(row) {
  if (!row) return null;
  let hr5min = [];
  let hrv5min = [];
  let tags = [];
  try { hr5min = JSON.parse(row.hr_5min_json || '[]'); } catch {}
  try { hrv5min = JSON.parse(row.hrv_5min_json || '[]'); } catch {}
  try { tags = JSON.parse(row.tags_json || '[]'); } catch {}

  return {
    userId: row.user_id,
    day: row.day,
    readiness: {
      score: row.readiness_score,
      tempDeviation: row.temp_deviation,
      tempTrendDeviation: row.temp_trend_deviation,
      contributors: {
        hrvBalance: row.hrv_balance_contrib,
        restingHeartRate: row.resting_hr_contrib,
        recoveryIndex: row.recovery_index_contrib,
        sleepBalance: row.sleep_balance_contrib,
        previousNight: row.previous_night_contrib,
        activityBalance: row.activity_balance_contrib
      }
    },
    sleep: {
      score: row.sleep_score,
      totalSeconds: row.total_sleep_seconds,
      deepSeconds: row.deep_sleep_seconds,
      remSeconds: row.rem_sleep_seconds,
      lightSeconds: row.light_sleep_seconds,
      awakeSeconds: row.awake_seconds,
      timeInBedSeconds: row.time_in_bed_seconds,
      efficiency: row.sleep_efficiency,
      latencySeconds: row.sleep_latency_seconds,
      lowestHr: row.lowest_hr,
      averageHr: row.average_hr,
      averageHrv: row.average_hrv,
      averageBreath: row.average_breath,
      bedtimeStart: row.bedtime_start,
      bedtimeEnd: row.bedtime_end,
      hypnogram5min: row.hypnogram_5min || '',
      hr5min,
      hrv5min
    },
    activity: {
      score: row.activity_score,
      steps: row.steps,
      activeCalories: row.active_calories,
      totalCalories: row.total_calories,
      walkingDistanceMeters: row.equivalent_walking_distance,
      highSeconds: row.high_activity_seconds,
      mediumSeconds: row.medium_activity_seconds,
      lowSeconds: row.low_activity_seconds,
      sedentarySeconds: row.sedentary_seconds,
      inactivityAlerts: row.inactivity_alerts
    },
    spo2: {
      percentage: row.spo2_percentage,
      breathingDisturbanceIndex: row.breathing_disturbance_index
    },
    stress: {
      stressHighSeconds: row.stress_high_seconds,
      recoveryHighSeconds: row.recovery_high_seconds,
      daySummary: row.stress_day_summary
    },
    tags,
    customNote: row.custom_note || ''
  };
}

export function toLocalDayStr(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

export function getLatestDayForUser(userId) {
  const row = db.prepare('SELECT MAX(day) as latest_day FROM daily_summaries WHERE user_id = ?').get(userId);
  return row?.latest_day || toLocalDayStr();
}

export function getSyncedDaysForUser(userId) {
  return db
    .prepare('SELECT day FROM daily_summaries WHERE user_id = ? ORDER BY day ASC')
    .all(userId)
    .map((r) => r.day);
}

export function clearUserSummariesForRealSync(userId) {
  db.prepare('DELETE FROM daily_summaries WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM heartrate_samples WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM workouts WHERE user_id = ?').run(userId);
}

export function getDailySummary(userId, day) {
  const row = db.prepare('SELECT * FROM daily_summaries WHERE user_id = ? AND day = ?').get(userId, day);
  return formatDailySummary(row);
}

export function getDailySummariesRange(userId, startDate, endDate) {
  const rows = db.prepare(`
    SELECT * FROM daily_summaries
    WHERE user_id = ? AND day >= ? AND day <= ?
    ORDER BY day ASC
  `).all(userId, startDate, endDate);
  return rows.map(formatDailySummary);
}

export function saveDailyNote(userId, day, customNote, tags) {
  const existing = db.prepare('SELECT * FROM daily_summaries WHERE user_id = ? AND day = ?').get(userId, day);
  if (!existing) {
    upsertDailySummary(userId, day, {
      custom_note: customNote,
      tags_json: Array.isArray(tags) ? JSON.stringify(tags) : '[]'
    });
  } else {
    db.prepare(`
      UPDATE daily_summaries
      SET custom_note = ?,
          tags_json = COALESCE(?, tags_json),
          updated_at = datetime('now')
      WHERE user_id = ? AND day = ?
    `).run(
      String(customNote ?? ''),
      Array.isArray(tags) ? JSON.stringify(tags) : null,
      userId,
      day
    );
  }
  return getDailySummary(userId, day);
}

export function replaceHeartrateDay(userId, day, samples) {
  db.prepare('DELETE FROM heartrate_samples WHERE user_id = ? AND day = ?').run(userId, day);
  const insert = db.prepare(`
    INSERT OR REPLACE INTO heartrate_samples (user_id, day, timestamp, bpm, source)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (const s of samples) {
    insert.run(userId, day, s.timestamp, s.bpm, s.source || 'awake');
  }
}

export function getHeartrateDay(userId, day) {
  return db.prepare(`
    SELECT timestamp, bpm, source
    FROM heartrate_samples
    WHERE user_id = ? AND day = ?
    ORDER BY timestamp ASC
  `).all(userId, day);
}

export function upsertWorkout(userId, workout) {
  db.prepare(`
    INSERT OR REPLACE INTO workouts (id, user_id, day, activity, calories, distance, start_datetime, end_datetime, intensity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    workout.id,
    userId,
    workout.day,
    workout.activity,
    workout.calories || 0,
    workout.distance || 0,
    workout.start_datetime || null,
    workout.end_datetime || null,
    workout.intensity || 'moderate'
  );
}

export function getWorkoutsForDay(userId, day) {
  return db.prepare(`
    SELECT id, day, activity, calories, distance, start_datetime as startDatetime, end_datetime as endDatetime, intensity
    FROM workouts
    WHERE user_id = ? AND day = ?
    ORDER BY start_datetime ASC
  `).all(userId, day);
}

export function getUserBaselines(userId, upToDay, windowDays = 30) {
  const rows = db.prepare(`
    SELECT
      AVG(readiness_score) as avg_readiness,
      AVG(sleep_score) as avg_sleep,
      AVG(activity_score) as avg_activity,
      AVG(lowest_hr) as avg_rhr,
      AVG(average_hrv) as avg_hrv,
      AVG(total_sleep_seconds) as avg_sleep_sec,
      AVG(deep_sleep_seconds) as avg_deep_sec,
      AVG(rem_sleep_seconds) as avg_rem_sec,
      AVG(steps) as avg_steps,
      AVG(spo2_percentage) as avg_spo2
    FROM (
      SELECT * FROM daily_summaries
      WHERE user_id = ? AND day <= ?
      ORDER BY day DESC
      LIMIT ?
    )
  `).get(userId, upToDay, windowDays);

  return {
    readiness: rows?.avg_readiness ? Math.round(rows.avg_readiness) : 80,
    sleep: rows?.avg_sleep ? Math.round(rows.avg_sleep) : 80,
    activity: rows?.avg_activity ? Math.round(rows.avg_activity) : 80,
    lowestHr: rows?.avg_rhr ? Number(rows.avg_rhr.toFixed(1)) : 54,
    averageHrv: rows?.avg_hrv ? Math.round(rows.avg_hrv) : 55,
    totalSleepSeconds: rows?.avg_sleep_sec ? Math.round(rows.avg_sleep_sec) : 27000,
    deepSleepSeconds: rows?.avg_deep_sec ? Math.round(rows.avg_deep_sec) : 5400,
    remSleepSeconds: rows?.avg_rem_sec ? Math.round(rows.avg_rem_sec) : 6000,
    steps: rows?.avg_steps ? Math.round(rows.avg_steps) : 8500,
    spo2: rows?.avg_spo2 ? Number(rows.avg_spo2.toFixed(1)) : 97.8
  };
}

export function addSyncLog(userId, { startedAt, finishedAt, status, daysSynced = 0, message = '' }) {
  db.prepare(`
    INSERT INTO sync_logs (user_id, started_at, finished_at, status, days_synced, message)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(userId, startedAt, finishedAt || new Date().toISOString(), status, daysSynced, message);
}

export function getSyncLogs(userId, limit = 15) {
  return db.prepare(`
    SELECT id, started_at as startedAt, finished_at as finishedAt, status, days_synced as daysSynced, message
    FROM sync_logs
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT ?
  `).all(userId, limit);
}

export function setUserSyncState(userId, { status, lastSyncedAt, error = null }) {
  db.prepare(`
    UPDATE users
    SET sync_status = ?,
        last_synced_at = COALESCE(?, last_synced_at),
        sync_error = ?
    WHERE id = ?
  `).run(status, lastSyncedAt || null, error, userId);
}

// --- Th0rgal/open_oura Cloud-Free Ring Storage Helpers ---

export function saveUserRingConfig(userId, { ringKeyHex, ringSerial, ringName }) {
  const current = getRawUserById(userId);
  if (!current) return null;

  let encKey = current.encrypted_ring_key;
  if (ringKeyHex !== undefined && ringKeyHex !== '') {
    const cleanHex = String(ringKeyHex).trim().toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{32}$/.test(cleanHex)) {
      throw new Error('Ring Auth Key must be 16 bytes (32 hex characters).');
    }
    encKey = encryptSecret(cleanHex);
  }

  const serial = ringSerial !== undefined ? String(ringSerial).trim() : (current.ring_serial || `OURA3-${userId}`);
  const name = ringName !== undefined ? String(ringName).trim() : current.ring_name;

  db.prepare(`
    UPDATE users
    SET encrypted_ring_key = ?,
        ring_serial = ?,
        ring_name = ?,
        auth_mode = CASE WHEN ? IS NOT NULL THEN 'ble' ELSE auth_mode END,
        sync_error = NULL
    WHERE id = ?
  `).run(encKey, serial, name, encKey, userId);

  return getUserById(userId);
}

export function getDecryptedRingKey(userId) {
  const row = getRawUserById(userId);
  if (!row || !row.encrypted_ring_key) return null;
  return decryptSecret(row.encrypted_ring_key);
}

export function disconnectUserRing(userId) {
  db.prepare(`
    UPDATE users
    SET encrypted_ring_key = NULL,
        encrypted_pat = NULL,
        encrypted_oauth_access = NULL,
        encrypted_oauth_refresh = NULL,
        oauth_expires_at = NULL,
        auth_mode = 'demo',
        sync_status = 'idle',
        sync_error = NULL
    WHERE id = ?
  `).run(userId);
  return getUserById(userId);
}

export function upsertRingDevice(userId, { serial, hwId, firmware, bootloader, batteryPercent, charging }) {
  const cleanSerial = String(serial || `OURA3-${userId}`).trim();
  const nowUnix = Math.floor(Date.now() / 1000);
  const existing = db.prepare('SELECT * FROM ring_devices WHERE serial = ?').get(cleanSerial) || {};

  const finalHw = hwId || existing.hw_id || '';
  const finalFw = firmware || existing.firmware || '';
  const finalBl = bootloader || existing.bootloader || '';
  const finalBat = batteryPercent !== undefined && batteryPercent !== null ? batteryPercent : (existing.battery_percent ?? null);
  const finalChg = charging !== undefined && charging !== null ? (charging ? 1 : 0) : (existing.charging ?? 0);

  db.prepare(`
    INSERT INTO ring_devices (serial, user_id, hw_id, firmware, bootloader, battery_percent, charging, last_seen_unix)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(serial) DO UPDATE SET
      user_id = excluded.user_id,
      hw_id = excluded.hw_id,
      firmware = excluded.firmware,
      bootloader = excluded.bootloader,
      battery_percent = excluded.battery_percent,
      charging = excluded.charging,
      last_seen_unix = excluded.last_seen_unix
  `).run(cleanSerial, userId, finalHw, finalFw, finalBl, finalBat, finalChg, nowUnix);

  db.prepare(`
    UPDATE users
    SET ring_serial = ?,
        ring_hw_id = CASE WHEN ? != '' THEN ? ELSE ring_hw_id END,
        ring_firmware = CASE WHEN ? != '' THEN ? ELSE ring_firmware END,
        ring_battery = COALESCE(?, ring_battery)
    WHERE id = ?
  `).run(cleanSerial, finalHw, finalHw, finalFw, finalFw, finalBat, userId);
}

export function getRingSyncCursor(userId, serial) {
  const cleanSerial = String(serial || `OURA3-${userId}`).trim();
  const row = db.prepare('SELECT last_timestamp FROM ring_sync_state WHERE serial = ?').get(cleanSerial);
  return row ? Number(row.last_timestamp) : 0;
}

export function setRingSyncCursor(userId, serial, lastTimestamp) {
  const cleanSerial = String(serial || `OURA3-${userId}`).trim();
  const nowUnix = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO ring_sync_state (serial, user_id, last_timestamp, updated_unix)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(serial) DO UPDATE SET
      last_timestamp = MAX(ring_sync_state.last_timestamp, excluded.last_timestamp),
      updated_unix = excluded.updated_unix
  `).run(cleanSerial, userId, Number(lastTimestamp || 0), nowUnix);

  db.prepare(`
    UPDATE users
    SET ring_cursor = MAX(COALESCE(ring_cursor, 0), ?),
        last_synced_at = datetime('now'),
        sync_status = 'idle'
    WHERE id = ?
  `).run(Number(lastTimestamp || 0), userId);
}

export function insertRingEvent(userId, { serial, tag, name, ringTimestamp, body, decoded, capturedUnix }) {
  const cleanSerial = String(serial || `OURA3-${userId}`).trim();
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body || []);
  const decodedJson = decoded ? (typeof decoded === 'string' ? decoded : JSON.stringify(decoded)) : null;
  const cap = Number(capturedUnix || Math.floor(Date.now() / 1000));

  db.prepare(`
    INSERT INTO ring_events (user_id, serial, tag, name, ring_timestamp, body, decoded_json, captured_unix)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(userId, cleanSerial, Number(tag), String(name), Number(ringTimestamp), bodyBuf, decodedJson, cap);
}

export function insertRingReading(userId, { serial, kind, payload, capturedUnix }) {
  const cleanSerial = String(serial || `OURA3-${userId}`).trim();
  const payloadJson = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
  const cap = Number(capturedUnix || Math.floor(Date.now() / 1000));

  db.prepare(`
    INSERT INTO ring_readings (user_id, serial, kind, payload_json, captured_unix)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, cleanSerial, String(kind), payloadJson, cap);
}

export function getRingEventsForUser(userId, limit = 5000) {
  return db.prepare(`
    SELECT id, serial, tag, name, ring_timestamp as ringTimestamp, body, decoded_json as decodedJson, captured_unix as capturedUnix
    FROM ring_events
    WHERE user_id = ?
    ORDER BY id ASC
    LIMIT ?
  `).all(userId, limit);
}

export function getRingOverviewForUser(userId) {
  const user = getUserById(userId);
  const rawUser = getRawUserById(userId);
  const keyHex = rawUser?.encrypted_ring_key ? decryptSecret(rawUser.encrypted_ring_key) : null;
  const maskedKey = keyHex ? `${keyHex.slice(0, 6)}…${keyHex.slice(-6)}` : null;

  const countsByName = db.prepare(`
    SELECT tag, name, COUNT(*) as count, MAX(ring_timestamp) as maxTimestamp
    FROM ring_events
    WHERE user_id = ?
    GROUP BY tag, name
    ORDER BY count DESC
  `).all(userId);

  const totalEventsRow = db.prepare('SELECT COUNT(*) as total FROM ring_events WHERE user_id = ?').get(userId);
  const recentEvents = db.prepare(`
    SELECT id, serial, tag, name, ring_timestamp as ringTimestamp, decoded_json as decodedJson, captured_unix as capturedUnix
    FROM ring_events
    WHERE user_id = ? AND decoded_json IS NOT NULL
    ORDER BY id DESC
    LIMIT 20
  `).all(userId).map((r) => {
    let decoded = null;
    try { decoded = JSON.parse(r.decodedJson); } catch {}
    return {
      id: r.id,
      serial: r.serial,
      tagHex: `0x${Number(r.tag).toString(16).padStart(2, '0')}`,
      name: r.name,
      ringTimestamp: r.ringTimestamp,
      capturedUnix: r.capturedUnix,
      decoded
    };
  });

  return {
    serial: user?.ringSerial || `OURA3-${userId}`,
    hasRingKey: Boolean(keyHex),
    maskedKey,
    ringKeyHex: keyHex,
    batteryPercent: user?.ringBattery ?? null,
    firmware: user?.ringFirmware || '',
    hwId: user?.ringHwId || '',
    cursor: user?.ringCursor || 0,
    totalEvents: totalEventsRow?.total || 0,
    countsByName: countsByName.map((c) => ({
      tagHex: `0x${Number(c.tag).toString(16).padStart(2, '0')}`,
      name: c.name,
      count: c.count,
      maxTimestamp: c.maxTimestamp
    })),
    recentEvents
  };
}
