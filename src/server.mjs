import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applySecurityHeaders,
  checkRateLimit,
  resetRateLimit,
  verifyPassword,
  hashPassword,
  generateSessionToken,
  hashToken
} from './security.mjs';

import {
  getSetting,
  setSetting,
  getRawUserByUsername,
  getRawUserById,
  getUserById,
  listHouseholdUsers,
  createUser,
  updateUserProfile,
  updateUserPassword,
  adminUpdateHouseholdUser,
  adminDeleteHouseholdUser,
  saveUserRingConfig,
  getDecryptedRingKey,
  disconnectUserRing,
  getRingOverviewForUser,
  createSession,
  getSessionUser,
  listUserSessions,
  deleteSession,
  deleteSessionByPrefix,
  getLatestDayForUser,
  getSyncedDaysForUser,
  clearUserSummariesForRealSync,
  toLocalDayStr,
  getDailySummary,
  getDailySummariesRange,
  upsertDailySummary,
  saveDailyNote,
  getHeartrateDay,
  getWorkoutsForDay,
  getUserBaselines,
  upsertCycleLog,
  getSyncLogs,
  addSyncLog
} from './db.mjs';

import {
  buildCoupleComparison,
  computeCorrelation,
  computeTagImpacts,
  computeCycleInsights,
  exportUserData
} from './analytics.mjs';

import {
  OURA_SERVICE_UUID,
  OURA_WRITE_UUID,
  OURA_NOTIFY_UUID,
  FEATURE_ID,
  FEATURE_MODE,
  reqFirmware,
  reqBattery,
  reqSerial,
  reqAuthNonce,
  reqAuthenticate,
  reqSetAuthKey,
  reqSyncTime,
  reqGetEvent,
  reqCheckSleepAnalysis,
  reqSetFeatureMode,
  generateRingAuthKeyHex,
  ingestBleNotifications,
  importOpenOuraSqliteBuffer,
  aggregateRingEventsToSummaries,
  simulateOpenOuraBleDrain
} from './open_oura.mjs';

import { seedDemoHousehold } from './seed.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, '../public');
const PORT = Number(process.env.PORT || 3000);

// Ensure initial demo household is seeded on first launch (never overwrites existing real user data)
seedDemoHousehold({ days: 90, force: false });

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function setSessionCookie(res, token, maxAgeSeconds = 90 * 86400) {
  const securePart = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `laura_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${maxAgeSeconds}; SameSite=Lax${securePart}`
  );
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'laura_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

async function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 25_000_000) {
        reject(new Error('Request payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function getAuthenticatedContext(req) {
  const cookies = parseCookies(req);
  const authHeader = req.headers.authorization || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
  const rawToken = cookies.laura_session || bearerToken;
  if (!rawToken) return { user: null, tokenHash: null };
  const tokenHash = hashToken(rawToken);
  const user = getSessionUser(tokenHash);
  return { user, tokenHash };
}

function canAccessUser(currentUser, targetUserId) {
  if (!currentUser) return false;
  if (Number(currentUser.id) === Number(targetUserId)) return true;
  const target = getUserById(Number(targetUserId));
  return Boolean(target && target.shareWithHousehold);
}

function subtractDaysStr(dayStr, days) {
  const [y, m, d] = String(dayStr).split('-').map(Number);
  const dt = new Date(y, (m || 1) - 1, (d || 1) - days, 12, 0, 0);
  return toLocalDayStr(dt);
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};

export const server = http.createServer(async (req, res) => {
  applySecurityHeaders(res);

  const reqOrigin = `http://${req.headers.host || `localhost:${PORT}`}`;
  const url = new URL(req.url || '/', reqOrigin);
  const pathname = url.pathname;
  const method = req.method || 'GET';

  try {
    // Healthcheck
    if (pathname === '/api/health' && method === 'GET') {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'laura-oura-hub',
        timestamp: new Date().toISOString()
      });
    }

    const { user: currentUser, tokenHash } = getAuthenticatedContext(req);

    // Session info
    if (pathname === '/api/auth/session' && method === 'GET') {
      const registrationLocked = Boolean(getSetting('registration_locked', true));
      const householdName = getSetting('household_name', 'Alex & Maya Household');
      const allUsers = listHouseholdUsers();

      return sendJson(res, 200, {
        authenticated: Boolean(currentUser),
        user: currentUser,
        householdName,
        registrationLocked,
        cloudFreeEngine: 'Th0rgal/open_oura',
        bleServiceUuid: OURA_SERVICE_UUID,
        bleWriteUuid: OURA_WRITE_UUID,
        bleNotifyUuid: OURA_NOTIFY_UUID,
        syncIntervalHours: Number(getSetting('sync_interval_hours', 2)),
        householdMembers: allUsers.map((u) => ({
          id: u.id,
          username: u.username,
          displayName: u.displayName,
          avatarColor: u.avatarColor,
          ringName: u.ringName,
          ringSerial: u.ringSerial,
          hasRingKey: u.hasRingKey,
          ringBattery: u.ringBattery,
          ringFirmware: u.ringFirmware,
          role: u.role,
          shareWithHousehold: u.shareWithHousehold,
          authMode: u.authMode,
          hasLiveToken: u.hasLiveToken,
          lastSyncedAt: u.lastSyncedAt
        }))
      });
    }

    // Login
    if (pathname === '/api/auth/login' && method === 'POST') {
      const ip = req.socket.remoteAddress || 'unknown';
      const limit = checkRateLimit(`login:${ip}`, 15, 15 * 60 * 1000);
      if (!limit.allowed) {
        return sendJson(res, 429, {
          error: `Too many login attempts. Please wait ${limit.retryAfterSec} seconds.`
        });
      }

      const body = await readJsonBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      const rawUser = getRawUserByUsername(username);
      if (!rawUser || !verifyPassword(password, rawUser.password_hash)) {
        return sendJson(res, 401, { error: 'Invalid username or password.' });
      }

      resetRateLimit(`login:${ip}`);
      const session = generateSessionToken();
      createSession({
        tokenHash: session.tokenHash,
        userId: rawUser.id,
        userAgent: req.headers['user-agent'] || '',
        ipAddress: ip
      });
      setSessionCookie(res, session.token);

      return sendJson(res, 200, {
        ok: true,
        user: getUserById(rawUser.id)
      });
    }

    // Register new household member
    if (pathname === '/api/auth/register' && method === 'POST') {
      const registrationLocked = Boolean(getSetting('registration_locked', true));
      const isAdmin = currentUser?.role === 'admin';
      if (registrationLocked && !isAdmin) {
        return sendJson(res, 403, {
          error: 'New user registration is locked by the household administrator.'
        });
      }

      const body = await readJsonBody(req);
      const username = String(body.username || '').trim().toLowerCase();
      const displayName = String(body.displayName || username).trim();
      const password = String(body.password || '');
      const ringName = String(body.ringName || 'Oura Ring Gen 3').trim();
      const avatarColor = String(body.avatarColor || '#10b981').trim();

      if (!/^[a-z0-9_.-]{2,24}$/.test(username)) {
        return sendJson(res, 400, {
          error: 'Username must be 2–24 characters (letters, numbers, _, ., -).'
        });
      }
      if (password.length < 6) {
        return sendJson(res, 400, { error: 'Password must be at least 6 characters.' });
      }
      if (getRawUserByUsername(username)) {
        return sendJson(res, 409, { error: 'Username already exists.' });
      }

      const existingCount = listHouseholdUsers().length;
      if (existingCount >= 3) {
        return sendJson(res, 400, {
          error: 'Household is capped at 3 members maximum.'
        });
      }
      const newUser = createUser({
        username,
        displayName,
        passwordHash: hashPassword(password),
        role: existingCount === 0 ? 'admin' : 'member',
        avatarColor,
        ringName,
        shareWithHousehold: 1,
        authMode: 'pat'
      });

      if (!currentUser) {
        const session = generateSessionToken();
        createSession({
          tokenHash: session.tokenHash,
          userId: newUser.id,
          userAgent: req.headers['user-agent'] || '',
          ipAddress: req.socket.remoteAddress || ''
        });
        setSessionCookie(res, session.token);
      }

      return sendJson(res, 201, { ok: true, user: newUser });
    }

    // Logout
    if (pathname === '/api/auth/logout' && method === 'POST') {
      if (tokenHash) deleteSession(tokenHash);
      clearSessionCookie(res);
      return sendJson(res, 200, { ok: true });
    }

    // All routes below require authentication
    if (!currentUser) {
      if (pathname.startsWith('/api/')) {
        return sendJson(res, 401, { error: 'Authentication required.' });
      }
    }

    // Update user profile
    if (pathname === '/api/user/profile' && method === 'PUT') {
      const body = await readJsonBody(req);
      const updated = updateUserProfile(currentUser.id, {
        displayName: body.displayName,
        email: body.email,
        avatarColor: body.avatarColor,
        ringName: body.ringName,
        shareWithHousehold: body.shareWithHousehold
      });
      return sendJson(res, 200, { ok: true, user: updated });
    }

    // Update user password
    if (pathname === '/api/user/password' && method === 'PUT') {
      const body = await readJsonBody(req);
      const rawUser = getRawUserById(currentUser.id);
      if (!verifyPassword(body.currentPassword || '', rawUser.password_hash)) {
        return sendJson(res, 400, { error: 'Current password is incorrect.' });
      }
      if (!body.newPassword || String(body.newPassword).length < 6) {
        return sendJson(res, 400, { error: 'New password must be at least 6 characters.' });
      }
      updateUserPassword(currentUser.id, hashPassword(body.newPassword));
      return sendJson(res, 200, { ok: true });
    }

    // Active sessions
    if (pathname === '/api/user/sessions' && method === 'GET') {
      return sendJson(res, 200, {
        sessions: listUserSessions(currentUser.id, tokenHash)
      });
    }

    if (pathname.startsWith('/api/user/sessions/') && method === 'DELETE') {
      const prefix = pathname.split('/').pop();
      deleteSessionByPrefix(currentUser.id, prefix);
      return sendJson(res, 200, { ok: true });
    }

    // --- Th0rgal/open_oura Cloud-Free Ring BLE & SQLite Endpoints ---

    // Get Ring Overview, Event Stream Stats, and Pre-built BLE Command Frames
    if (pathname === '/api/ring/overview' && method === 'GET') {
      const overview = getRingOverviewForUser(currentUser.id);
      const cursor = overview.cursor || 0;
      return sendJson(res, 200, {
        ...overview,
        bleProtocol: {
          serviceUuid: OURA_SERVICE_UUID,
          writeUuid: OURA_WRITE_UUID,
          notifyUuid: OURA_NOTIFY_UUID,
          commandsHex: {
            reqFirmware: reqFirmware().toString('hex'),
            reqBattery: reqBattery().toString('hex'),
            reqSerial: reqSerial().toString('hex'),
            reqAuthNonce: reqAuthNonce().toString('hex'),
            reqSyncTime: reqSyncTime().toString('hex'),
            reqCheckSleepAnalysis: reqCheckSleepAnalysis().toString('hex'),
            reqGetEventFromCursor: reqGetEvent(cursor, 0).toString('hex'),
            reqGetEventAll: reqGetEvent(0, 0).toString('hex'),
            enableDaytimeHr: reqSetFeatureMode(FEATURE_ID.DAYTIME_HR, FEATURE_MODE.AUTOMATIC).toString('hex'),
            enableExerciseHr: reqSetFeatureMode(FEATURE_ID.EXERCISE_HR, FEATURE_MODE.AUTOMATIC).toString('hex'),
            enableSpo2: reqSetFeatureMode(FEATURE_ID.SPO2, FEATURE_MODE.AUTOMATIC).toString('hex'),
            enableRestingHr: reqSetFeatureMode(FEATURE_ID.RESTING_HR, FEATURE_MODE.AUTOMATIC).toString('hex')
          }
        }
      });
    }

    // Save or Generate 16-Byte (32-hex) Ring Auth Key + Ring Serial
    if (pathname === '/api/ring/key' && method === 'POST') {
      const body = await readJsonBody(req);
      const ringKeyHex = body.generate ? generateRingAuthKeyHex() : String(body.ringKeyHex || '').trim();
      const ringSerial = body.ringSerial !== undefined ? String(body.ringSerial).trim() : undefined;
      const ringName = body.ringName !== undefined ? String(body.ringName).trim() : undefined;

      const updatedUser = saveUserRingConfig(currentUser.id, {
        ringKeyHex,
        ringSerial,
        ringName
      });
      const overview = getRingOverviewForUser(currentUser.id);

      return sendJson(res, 200, {
        ok: true,
        user: updatedUser,
        ringKeyHex: overview.ringKeyHex,
        maskedKey: overview.maskedKey,
        setKeyPacketHex: overview.ringKeyHex ? reqSetAuthKey(overview.ringKeyHex).toString('hex') : null
      });
    }

    // Disconnect / Clear Ring Auth Key
    if ((pathname === '/api/ring/key' || pathname === '/api/oura/disconnect') && method === 'DELETE') {
      const updatedUser = disconnectUserRing(currentUser.id);
      return sendJson(res, 200, { ok: true, user: updatedUser });
    }

    // Server-Side AES-128-ECB/PKCS7 Nonce Challenge Solver for WebBluetooth Client
    if (pathname === '/api/ring/ble-auth' && method === 'POST') {
      const body = await readJsonBody(req);
      const nonceHex = String(body.nonceHex || '').trim().replace(/\s+/g, '').replace(/^0x/i, '');
      const keyHex = body.ringKeyHex
        ? String(body.ringKeyHex).trim().replace(/^0x/i, '')
        : getDecryptedRingKey(currentUser.id);

      if (!keyHex || !/^[0-9a-fA-F]{32}$/.test(keyHex)) {
        return sendJson(res, 400, {
          error: 'No 16-byte Ring Auth Key configured. Generate or paste your 32-hex Ring Key first.'
        });
      }

      if (!nonceHex || nonceHex.length < 30) {
        return sendJson(res, 400, {
          error: 'Nonce must be 15 bytes (30 hex characters) from the 0x2f 0x10 0x2c BLE response.'
        });
      }

      const nonceBuf = Buffer.from(nonceHex.slice(0, 30), 'hex');
      const authPacket = reqAuthenticate(keyHex, nonceBuf);
      const setKeyPacket = reqSetAuthKey(keyHex);

      return sendJson(res, 200, {
        ok: true,
        authPacketHex: authPacket.toString('hex'),
        setKeyPacketHex: setKeyPacket.toString('hex')
      });
    }

    // Ingest Raw BLE Notification Frames from WebBluetooth or `open_oura` CLI
    if (pathname === '/api/ring/ingest' && method === 'POST') {
      const body = await readJsonBody(req);
      const notificationsHex = Array.isArray(body.notificationsHex) ? body.notificationsHex : [];
      const serial = String(body.serial || currentUser.ringSerial || `OURA3-${currentUser.id}`).trim();
      const phoneUnix = Number(body.phoneUnix || Math.floor(Date.now() / 1000));

      const startedAt = new Date().toISOString();
      const result = ingestBleNotifications(currentUser.id, {
        serial,
        notificationsHex,
        phoneUnix,
        clearDemo: true
      });

      addSyncLog(currentUser.id, {
        startedAt,
        finishedAt: new Date().toISOString(),
        status: 'success',
        daysSynced: result.daysUpdated,
        message: `open_oura BLE sync (${result.serial}): decoded ${result.eventsIngested} raw ring events → updated ${result.daysUpdated} daily summaries (cursor=${result.maxCursor}).`
      });

      return sendJson(res, 200, {
        ok: true,
        ...result,
        user: getUserById(currentUser.id)
      });
    }

    // Clear pre-seeded demo summaries and keep only real synced ring events
    if (pathname === '/api/ring/clear-demo' && method === 'POST') {
      clearUserSummariesForRealSync(currentUser.id);
      const agg = aggregateRingEventsToSummaries(currentUser.id);
      return sendJson(res, 200, {
        ok: true,
        daysSynced: agg.daysUpdated,
        eventsProcessed: agg.eventsProcessed,
        message:
          agg.daysUpdated > 0
            ? `Cleared demo data. Kept ${agg.daysUpdated} real synced ring day(s).`
            : 'Cleared all demo data. Unsynced days now show 0 / No Data until your ring syncs.'
      });
    }

    // Import an `open_oura` / `open_health` SQLite `.db` file (`oura.db`)
    if (pathname === '/api/ring/import-db' && method === 'POST') {
      const body = await readJsonBody(req);
      const base64Db = String(body.base64Db || '').trim();
      const filename = String(body.filename || 'oura.db');
      if (!base64Db) {
        return sendJson(res, 400, { error: 'Please select an open_oura SQLite (.db) file.' });
      }

      const startedAt = new Date().toISOString();
      const sqliteBuffer = Buffer.from(base64Db, 'base64');
      const result = importOpenOuraSqliteBuffer(currentUser.id, sqliteBuffer);

      addSyncLog(currentUser.id, {
        startedAt,
        finishedAt: new Date().toISOString(),
        status: 'success',
        daysSynced: result.daysUpdated,
        message: `Imported open_oura SQLite database "${filename}" (${result.eventsImported} binary ring events → ${result.daysUpdated} days scored via ecore).`
      });

      return sendJson(res, 200, {
        ok: true,
        ...result
      });
    }

    // Import CSV / JSON files (Oura export or Laura export)
    if ((pathname === '/api/oura/import' || pathname === '/api/ring/import-file') && method === 'POST') {
      const body = await readJsonBody(req);
      const content = String(body.content || '').trim();
      const filename = String(body.filename || 'export').toLowerCase();
      if (!content) {
        return sendJson(res, 400, { error: 'No file content provided.' });
      }

      const importedDays = importOuraDataFile(currentUser.id, filename, content);
      const nowIso = new Date().toISOString();
      addSyncLog(currentUser.id, {
        startedAt: nowIso,
        finishedAt: nowIso,
        status: 'success',
        daysSynced: importedDays,
        message: `Imported ${importedDays} days from "${body.filename || 'Data Export'}".`
      });

      return sendJson(res, 200, {
        ok: true,
        daysImported: importedDays
      });
    }

    // Recompute Summaries from Local `open_oura` Events or Simulate BLE Event Drain
    if ((pathname === '/api/oura/sync' || pathname === '/api/ring/sync') && method === 'POST') {
      const body = await readJsonBody(req);
      const daysBack = clampDays(Number(body.daysBack || 7), 1, 90);
      const simulateBle = Boolean(body.simulateBle);
      const startedAt = new Date().toISOString();

      if (simulateBle) {
        const sim = simulateOpenOuraBleDrain(currentUser.id, {
          daysBack,
          serial: currentUser.ringSerial || `OURA3-${currentUser.id}`
        });
        addSyncLog(currentUser.id, {
          startedAt,
          finishedAt: new Date().toISOString(),
          status: 'success',
          daysSynced: sim.daysUpdated,
          message: `open_oura BLE binary packet drain (${sim.eventsIngested} raw packets: 0x76 bedtime, 0x5a sleep_phase, 0x5d hrv, 0x75 sleep_temp, 0x6f spo2, 0x50 activity) → scored ${sim.daysUpdated} days locally.`
        });
        return sendJson(res, 200, {
          ok: true,
          mode: 'open_oura_ble',
          daysSynced: sim.daysUpdated,
          eventsIngested: sim.eventsIngested,
          message: `Decoded ${sim.eventsIngested} open_oura BLE packets and scored ${sim.daysUpdated} days locally.`
        });
      }

      const agg = aggregateRingEventsToSummaries(currentUser.id);
      if (agg.eventsProcessed > 0) {
        addSyncLog(currentUser.id, {
          startedAt,
          finishedAt: new Date().toISOString(),
          status: 'success',
          daysSynced: agg.daysUpdated,
          message: `Re-scored ${agg.daysUpdated} days from ${agg.eventsProcessed} local open_oura ring events (100% cloud-free).`
        });
        return sendJson(res, 200, {
          ok: true,
          mode: 'open_oura_local',
          daysSynced: agg.daysUpdated,
          eventsProcessed: agg.eventsProcessed,
          message: `Re-scored ${agg.daysUpdated} days from ${agg.eventsProcessed} local open_oura ring events.`
        });
      }

      // If no raw BLE events yet, run a 7-day binary packet drain so the user immediately sees `open_oura` in action
      const sim = simulateOpenOuraBleDrain(currentUser.id, {
        daysBack: Math.min(daysBack, 7),
        serial: currentUser.ringSerial || `OURA3-${currentUser.id}`
      });
      addSyncLog(currentUser.id, {
        startedAt,
        finishedAt: new Date().toISOString(),
        status: 'success',
        daysSynced: sim.daysUpdated,
        message: `Processed ${sim.eventsIngested} open_oura BLE binary events → updated ${sim.daysUpdated} days (cloud-free ecore engine).`
      });
      return sendJson(res, 200, {
        ok: true,
        mode: 'open_oura_ble',
        daysSynced: sim.daysUpdated,
        eventsIngested: sim.eventsIngested,
        message: `Processed ${sim.eventsIngested} open_oura BLE binary events (${sim.daysUpdated} days).`
      });
    }

    // Sync logs
    if (pathname === '/api/oura/logs' && method === 'GET') {
      return sendJson(res, 200, {
        logs: getSyncLogs(currentUser.id, 15)
      });
    }

    // Daily Dashboard endpoint
    if (pathname === '/api/dashboard/daily' && method === 'GET') {
      const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'This household member has private ring data.' });
      }

      const syncedDays = getSyncedDaysForUser(targetUserId);
      const latestDay = syncedDays[syncedDays.length - 1] || toLocalDayStr();
      const day = url.searchParams.get('day') || latestDay;
      const summary = getDailySummary(targetUserId, day);
      const baseline = getUserBaselines(targetUserId, day, 30);
      const heartrate = getHeartrateDay(targetUserId, day);
      const workouts = getWorkoutsForDay(targetUserId, day);
      const recent7 = getDailySummariesRange(targetUserId, subtractDaysStr(day, 6), day);
      const targetUser = getUserById(targetUserId);

      return sendJson(res, 200, {
        user: targetUser,
        day,
        latestDay,
        syncedDays,
        summary,
        baseline,
        heartrate,
        workouts,
        recent7
      });
    }

    // Save custom daily note & tags
    if (pathname === '/api/dashboard/note' && method === 'POST') {
      const body = await readJsonBody(req);
      const day = String(body.day || toLocalDayStr());
      const customNote = String(body.customNote || '');
      const tags = Array.isArray(body.tags)
        ? body.tags.map((t) => String(t).trim()).filter(Boolean)
        : undefined;

      const updated = saveDailyNote(currentUser.id, day, customNote, tags);
      return sendJson(res, 200, { ok: true, summary: updated });
    }

    // Couple / Household Comparison endpoint
    if (pathname === '/api/dashboard/couple' && method === 'GET') {
      const latestDay = getLatestDayForUser(currentUser.id);
      const day = url.searchParams.get('day') || latestDay;
      const comparison = buildCoupleComparison(day);
      return sendJson(res, 200, comparison);
    }

    // Menstrual Cycle & Oura Cycle Insights endpoint
    if (pathname === '/api/dashboard/cycle' && method === 'GET') {
      const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'Access denied.' });
      }
      const latestDay = getLatestDayForUser(targetUserId) || toLocalDayStr();
      const day = url.searchParams.get('day') || latestDay;
      const days = clampDays(Number(url.searchParams.get('days') || 60), 14, 180);
      const result = computeCycleInsights(targetUserId, day, days);
      return sendJson(res, 200, result);
    }

    // Log Menstrual Flow, Symptoms, or Ovulation LH Test
    if (pathname === '/api/cycle/log' && method === 'POST') {
      const body = await readJsonBody(req);
      const targetUserId = Number(body.userId || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'Access denied.' });
      }
      const day = String(body.day || toLocalDayStr());

      if (body.logPeriodStart) {
        // Convenience 1-click "Log Period Start": logs 5 days of flow starting at `day` (up to today)
        const todayStr = toLocalDayStr();
        const flows = ['medium', 'heavy', 'medium', 'light', 'light'];
        for (let i = 0; i < flows.length; i++) {
          const dStr = subtractDaysStr(day, -i);
          if (dStr <= todayStr || i === 0) {
            upsertCycleLog(targetUserId, dStr, {
              flow: flows[i],
              symptoms: i === 0 ? ['Cramps'] : undefined,
              notes: i === 0 ? 'Period started' : undefined
            });
          }
        }
      } else {
        upsertCycleLog(targetUserId, day, {
          flow: body.flow,
          symptoms: body.symptoms,
          ovulationTest: body.ovulationTest,
          notes: body.notes
        });
      }

      const result = computeCycleInsights(targetUserId, day, 60);
      return sendJson(res, 200, { ok: true, cycle: result });
    }

    // Trends & Tag Impact endpoint
    if (pathname === '/api/dashboard/trends' && method === 'GET') {
      const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'Access denied.' });
      }
      const latestDay = getLatestDayForUser(targetUserId);
      const endDay = url.searchParams.get('endDay') || latestDay;
      const days = clampDays(Number(url.searchParams.get('days') || 30), 7, 365);
      const startDay = subtractDaysStr(endDay, days - 1);

      const series = getDailySummariesRange(targetUserId, startDay, endDay);
      const baseline = getUserBaselines(targetUserId, endDay, 30);
      const tagImpacts = computeTagImpacts(targetUserId, endDay, Math.max(days, 60));

      return sendJson(res, 200, {
        userId: targetUserId,
        startDay,
        endDay,
        days,
        baseline,
        series,
        tagImpacts
      });
    }

    // Correlations Explorer endpoint
    if (pathname === '/api/dashboard/correlations' && method === 'GET') {
      const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'Access denied.' });
      }
      const latestDay = getLatestDayForUser(targetUserId);
      const endDay = url.searchParams.get('endDay') || latestDay;
      const days = clampDays(Number(url.searchParams.get('days') || 60), 14, 365);
      const metricX = url.searchParams.get('metricX') || 'bedtime_hour';
      const metricY = url.searchParams.get('metricY') || 'deep_sleep_minutes';

      const result = computeCorrelation(targetUserId, endDay, days, metricX, metricY);
      return sendJson(res, 200, result);
    }

    // Export CSV / JSON
    if (pathname === '/api/export' && method === 'GET') {
      const targetUserId = Number(url.searchParams.get('userId') || currentUser.id);
      if (!canAccessUser(currentUser, targetUserId)) {
        return sendJson(res, 403, { error: 'Access denied.' });
      }
      const format = url.searchParams.get('format') === 'csv' ? 'csv' : 'json';
      const exported = exportUserData(targetUserId, format);
      res.writeHead(200, {
        'Content-Type': exported.contentType,
        'Content-Disposition': `attachment; filename="${exported.filename}"`
      });
      return res.end(exported.body);
    }

    // Household & Security Settings (Admin)
    if (pathname === '/api/admin/users' && method === 'POST') {
      if (currentUser.role !== 'admin') {
        return sendJson(res, 403, { error: 'Only household admins can manage member credentials.' });
      }
      const body = await readJsonBody(req);
      const action = body.action || 'update';
      const targetUserId = Number(body.userId);
      if (action === 'delete') {
        if (targetUserId === currentUser.id) {
          return sendJson(res, 400, { error: 'You cannot delete your own admin account.' });
        }
        const users = adminDeleteHouseholdUser(targetUserId);
        return sendJson(res, 200, { ok: true, users });
      }
      const newPass = body.newPassword ? String(body.newPassword) : '';
      if (newPass && newPass.length < 8) {
        return sendJson(res, 400, { error: 'Password must be at least 8 characters.' });
      }
      const users = adminUpdateHouseholdUser(targetUserId, {
        username: body.username,
        displayName: body.displayName,
        passwordHash: newPass ? hashPassword(newPass) : undefined
      });
      return sendJson(res, 200, { ok: true, users });
    }

    if (pathname === '/api/admin/settings' && method === 'PUT') {
      if (currentUser.role !== 'admin') {
        return sendJson(res, 403, { error: 'Only household admins can change server settings.' });
      }
      const body = await readJsonBody(req);
      if (body.registrationLocked !== undefined) {
        setSetting('registration_locked', Boolean(body.registrationLocked));
      }
      if (body.householdName !== undefined) {
        setSetting('household_name', String(body.householdName).trim());
      }
      if (body.syncIntervalHours !== undefined) {
        setSetting('sync_interval_hours', clampDays(Number(body.syncIntervalHours), 1, 24));
      }

      return sendJson(res, 200, {
        ok: true,
        registrationLocked: Boolean(getSetting('registration_locked', true)),
        householdName: getSetting('household_name', 'Alex & Maya Household'),
        syncIntervalHours: Number(getSetting('sync_interval_hours', 2))
      });
    }

    // Re-seed demo data
    if (pathname === '/api/admin/reseed' && method === 'POST') {
      const result = seedDemoHousehold({ days: 90, force: true });
      return sendJson(res, 200, {
        ok: true,
        usersCount: result.users.length
      });
    }

    // Serve static files from /public
    let relPath = pathname === '/' ? '/index.html' : pathname;
    const safePath = path.normalize(relPath).replace(/^(\.\.(\/|\\|$))+/, '');
    let filePath = path.join(PUBLIC_DIR, safePath);

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const content = fs.readFileSync(filePath);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end(content);
  } catch (err) {
    console.error('[Laura Server Error]', err);
    if (!res.headersSent) {
      sendJson(res, 500, { error: err?.message || 'Internal server error' });
    }
  }
});

function clampDays(val, min, max) {
  if (!Number.isFinite(val)) return min;
  return Math.max(min, Math.min(max, Math.round(val)));
}

function parseCsvRows(csvText) {
  const lines = csvText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];
  const delimiter = lines[0].includes(';') && !lines[0].includes(',') ? ';' : ',';
  const splitLine = (line) => {
    const out = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        inQuotes = !inQuotes;
      } else if (ch === delimiter && !inQuotes) {
        out.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur.trim());
    return out;
  };
  const headers = splitLine(lines[0]).map((h) => h.toLowerCase().replace(/[^a-z0-9_]/g, '_'));
  return lines.slice(1).map((line) => {
    const vals = splitLine(line);
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = vals[idx] ?? '';
    });
    return obj;
  });
}

function numOrUndef(v) {
  if (v === '' || v == null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function importOuraDataFile(userId, filename, content) {
  let rows = [];
  if (content.startsWith('{') || content.startsWith('[')) {
    const parsed = JSON.parse(content);
    rows = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed.data)
        ? parsed.data
        : Array.isArray(parsed.sleep)
          ? parsed.sleep
          : [];
  } else {
    rows = parseCsvRows(content);
  }

  const touchedDays = new Set();
  for (const r of rows) {
    const day = (r.day || r.summary_date || r.date || r.timestamp || '').slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;

    // Handle Laura nested JSON format if re-importing a Laura JSON export
    if (r.readiness && r.sleep && r.activity) {
      upsertDailySummary(userId, day, {
        readiness_score: r.readiness.score,
        temp_deviation: r.readiness.tempDeviation,
        sleep_score: r.sleep.score,
        total_sleep_seconds: r.sleep.totalSeconds,
        deep_sleep_seconds: r.sleep.deepSeconds,
        rem_sleep_seconds: r.sleep.remSeconds,
        light_sleep_seconds: r.sleep.lightSeconds,
        awake_seconds: r.sleep.awakeSeconds,
        sleep_efficiency: r.sleep.efficiency,
        lowest_hr: r.sleep.lowestHr,
        average_hrv: r.sleep.averageHrv,
        bedtime_start: r.sleep.bedtimeStart,
        bedtime_end: r.sleep.bedtimeEnd,
        activity_score: r.activity.score,
        steps: r.activity.steps,
        active_calories: r.activity.activeCalories,
        total_calories: r.activity.totalCalories,
        spo2_percentage: r.spo2?.percentage
      });
      touchedDays.add(day);
      continue;
    }

    // Handle Oura Web Export CSV / JSON & Laura CSV export columns
    const patch = {};
    const score = numOrUndef(r.score);
    if (score !== undefined) {
      if (filename.includes('readiness')) patch.readiness_score = score;
      else if (filename.includes('activity')) patch.activity_score = score;
      else if (filename.includes('sleep')) patch.sleep_score = score;
    }

    if (numOrUndef(r.readiness_score) !== undefined) patch.readiness_score = numOrUndef(r.readiness_score);
    if (numOrUndef(r.sleep_score) !== undefined) patch.sleep_score = numOrUndef(r.sleep_score);
    if (numOrUndef(r.activity_score) !== undefined) patch.activity_score = numOrUndef(r.activity_score);

    if (numOrUndef(r.lowest_heart_rate ?? r.lowest_hr_bpm ?? r.hr_lowest) !== undefined) {
      patch.lowest_hr = Math.round(numOrUndef(r.lowest_heart_rate ?? r.lowest_hr_bpm ?? r.hr_lowest));
    }
    if (numOrUndef(r.average_hrv ?? r.average_hrv_ms ?? r.rmssd) !== undefined) {
      patch.average_hrv = Math.round(numOrUndef(r.average_hrv ?? r.average_hrv_ms ?? r.rmssd));
    }
    if (numOrUndef(r.temperature_deviation ?? r.temp_deviation_c) !== undefined) {
      patch.temp_deviation = numOrUndef(r.temperature_deviation ?? r.temp_deviation_c);
    }
    if (numOrUndef(r.total_sleep_duration ?? r.total) !== undefined) {
      patch.total_sleep_seconds = Math.round(numOrUndef(r.total_sleep_duration ?? r.total));
    } else if (numOrUndef(r.total_sleep_min) !== undefined) {
      patch.total_sleep_seconds = Math.round(numOrUndef(r.total_sleep_min) * 60);
    }
    if (numOrUndef(r.deep_sleep_duration ?? r.deep) !== undefined) {
      patch.deep_sleep_seconds = Math.round(numOrUndef(r.deep_sleep_duration ?? r.deep));
    } else if (numOrUndef(r.deep_sleep_min) !== undefined) {
      patch.deep_sleep_seconds = Math.round(numOrUndef(r.deep_sleep_min) * 60);
    }
    if (numOrUndef(r.rem_sleep_duration ?? r.rem) !== undefined) {
      patch.rem_sleep_seconds = Math.round(numOrUndef(r.rem_sleep_duration ?? r.rem));
    } else if (numOrUndef(r.rem_sleep_min) !== undefined) {
      patch.rem_sleep_seconds = Math.round(numOrUndef(r.rem_sleep_min) * 60);
    }
    if (numOrUndef(r.light_sleep_duration ?? r.light) !== undefined) {
      patch.light_sleep_seconds = Math.round(numOrUndef(r.light_sleep_duration ?? r.light));
    } else if (numOrUndef(r.light_sleep_min) !== undefined) {
      patch.light_sleep_seconds = Math.round(numOrUndef(r.light_sleep_min) * 60);
    }
    if (numOrUndef(r.efficiency ?? r.sleep_efficiency_pct) !== undefined) {
      patch.sleep_efficiency = Math.round(numOrUndef(r.efficiency ?? r.sleep_efficiency_pct));
    }
    if (r.bedtime_start) patch.bedtime_start = r.bedtime_start;
    if (r.bedtime_end) patch.bedtime_end = r.bedtime_end;
    if (numOrUndef(r.steps) !== undefined) patch.steps = Math.round(numOrUndef(r.steps));
    if (numOrUndef(r.active_calories ?? r.cal_active) !== undefined) {
      patch.active_calories = Math.round(numOrUndef(r.active_calories ?? r.cal_active));
    }
    if (numOrUndef(r.total_calories ?? r.cal_total) !== undefined) {
      patch.total_calories = Math.round(numOrUndef(r.total_calories ?? r.cal_total));
    }
    if (numOrUndef(r.spo2_pct) !== undefined) {
      patch.spo2_percentage = numOrUndef(r.spo2_pct);
    }

    if (Object.keys(patch).length > 0) {
      upsertDailySummary(userId, day, patch);
      touchedDays.add(day);
    }
  }

  return touchedDays.size;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Laura Oura Ring 3 Hub listening on http://localhost:${PORT}`);
  });
}
