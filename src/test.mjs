import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Use an isolated temporary database directory so tests never touch live ring data
const TEST_DATA_DIR = path.resolve('./data/test-tmp');
if (fs.existsSync(TEST_DATA_DIR)) {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
}
process.env.DATA_DIR = TEST_DATA_DIR;

const { encryptSecret, decryptSecret, hashPassword, verifyPassword } = await import('./security.mjs');
const { encryptAuthNonce, decodeEventBody } = await import('./open_oura.mjs');
const { server } = await import('./server.mjs');

async function runTests() {
  console.log('1. Testing AES-256-GCM encryption & scrypt password hashing...');
  const rawToken = 'oura_oauth_secret_test_token_12345';
  const encrypted = encryptSecret(rawToken);
  assert.notEqual(encrypted, rawToken);
  const decrypted = decryptSecret(encrypted);
  assert.equal(decrypted, rawToken);

  const pwHash = hashPassword('my-super-secret');
  assert.equal(verifyPassword('my-super-secret', pwHash), true);
  assert.equal(verifyPassword('wrong-password', pwHash), false);

  console.log('2. Starting test HTTP server...');
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // Healthcheck
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.status, 'ok');

    // Unauthenticated access to protected route should return 401
    const unauthRes = await fetch(`${baseUrl}/api/dashboard/daily`);
    assert.equal(unauthRes.status, 401);

    // Registration should be locked by default after demo household seed
    const regLockedRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'stranger', password: 'password123' })
    });
    assert.equal(regLockedRes.status, 403);

    // Login as Alex
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alex', password: 'laura2026' })
    });
    assert.equal(loginRes.status, 200);
    const cookieHeader = loginRes.headers.get('set-cookie');
    assert.ok(cookieHeader && cookieHeader.includes('laura_session='));
    const cookie = cookieHeader.split(';')[0];

    // Fetch Daily Dashboard
    const dailyRes = await fetch(`${baseUrl}/api/dashboard/daily`, {
      headers: { Cookie: cookie }
    });
    assert.equal(dailyRes.status, 200);
    const daily = await dailyRes.json();
    assert.ok(daily.summary?.readiness?.score > 0);
    assert.ok(daily.summary?.sleep?.score > 0);
    assert.ok(daily.summary?.sleep?.hypnogram5min.length > 10);
    assert.ok(daily.heartrate.length > 20);

    // Fetch Couple Comparison
    const coupleRes = await fetch(`${baseUrl}/api/dashboard/couple`, {
      headers: { Cookie: cookie }
    });
    assert.equal(coupleRes.status, 200);
    const couple = await coupleRes.json();
    assert.equal(couple.members.length, 2);
    assert.ok(couple.sleepOverlap?.overlapPercent > 0);
    assert.ok(couple.briefing?.headline);

    // Fetch Trends & Tag Impacts
    const trendsRes = await fetch(`${baseUrl}/api/dashboard/trends?days=30`, {
      headers: { Cookie: cookie }
    });
    assert.equal(trendsRes.status, 200);
    const trends = await trendsRes.json();
    assert.equal(trends.series.length, 30);
    assert.ok(trends.tagImpacts.length >= 3);

    // Fetch Correlations Explorer
    const corrRes = await fetch(
      `${baseUrl}/api/dashboard/correlations?days=60&metricX=bedtime_hour&metricY=deep_sleep_minutes`,
      { headers: { Cookie: cookie } }
    );
    assert.equal(corrRes.status, 200);
    const corr = await corrRes.json();
    assert.equal(corr.points.length, 60);
    assert.ok(typeof corr.pearsonR === 'number');

    // Save custom daily note
    const noteRes = await fetch(`${baseUrl}/api/dashboard/note`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        day: daily.day,
        customNote: 'Tested note persistence!',
        tags: ['Magnesium', 'Sauna']
      })
    });
    assert.equal(noteRes.status, 200);
    const noteData = await noteRes.json();
    assert.equal(noteData.summary.customNote, 'Tested note persistence!');

    // Export CSV
    const csvRes = await fetch(`${baseUrl}/api/export?format=csv`, {
      headers: { Cookie: cookie }
    });
    assert.equal(csvRes.status, 200);
    const csvText = await csvRes.text();
    assert.ok(csvText.startsWith('day,readiness_score,sleep_score'));
    assert.ok(csvText.split('\n').length >= 90);

    // 9. Test Th0rgal/open_oura AES-128-ECB/PKCS7 Known-Answer Auth Challenge Vector
    const keyHex = '4431967d8bacc2659743142b68391d9a';
    const nonceBuf = Buffer.from('0e2d6a0a08c99b4365f458e6e97382', 'hex');
    const solvedCipher = encryptAuthNonce(keyHex, nonceBuf);
    assert.equal(solvedCipher.toString('hex'), 'a38a8772d3acb6db5c2b516dd56987c8');

    // 10. Save 16-Byte Ring Auth Key & test `/api/ring/ble-auth`
    const keyRes = await fetch(`${baseUrl}/api/ring/key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        ringSerial: 'OURA3-ALEX',
        ringKeyHex: keyHex
      })
    });
    assert.equal(keyRes.status, 200);
    const keyData = await keyRes.json();
    assert.equal(keyData.ringKeyHex, keyHex);

    const bleAuthRes = await fetch(`${baseUrl}/api/ring/ble-auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        nonceHex: '0e2d6a0a08c99b4365f458e6e97382'
      })
    });
    assert.equal(bleAuthRes.status, 200);
    const bleAuthData = await bleAuthRes.json();
    assert.equal(bleAuthData.authPacketHex, '2f112da38a8772d3acb6db5c2b516dd56987c8');

    // 11. Test open_oura Binary BLE Event Drain & ecore Scoring
    const bleSyncRes = await fetch(`${baseUrl}/api/ring/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ daysBack: 7, simulateBle: true })
    });
    assert.equal(bleSyncRes.status, 200);
    const bleSyncData = await bleSyncRes.json();
    assert.ok(bleSyncData.eventsIngested >= 120);
    assert.ok(bleSyncData.daysSynced >= 7);

    // Verify bedtimeStart is anchored to local device evening time (not 4 PM / UTC offset bug)
    const syncedDailyRes = await fetch(`${baseUrl}/api/dashboard/daily`, {
      headers: { Cookie: cookie }
    });
    const syncedDaily = await syncedDailyRes.json();
    const bedLocalHour = new Date(syncedDaily.summary.sleep.bedtimeStart).getHours();
    assert.ok(
      bedLocalHour >= 20 || bedLocalHour <= 2,
      `Expected bedtime in local evening hours (20..02), got local hour ${bedLocalHour}`
    );

    // Verify unsynced date returns summary: null and empty heartrate (no fallback to latestDay)
    const unsyncedRes = await fetch(`${baseUrl}/api/dashboard/daily?day=2020-01-01`, {
      headers: { Cookie: cookie }
    });
    const unsyncedData = await unsyncedRes.json();
    assert.equal(unsyncedData.summary, null);
    assert.equal(unsyncedData.heartrate.length, 0);

    // 12. Verify `/api/ring/overview` returns decoded binary event counts
    const ovRes = await fetch(`${baseUrl}/api/ring/overview`, {
      headers: { Cookie: cookie }
    });
    assert.equal(ovRes.status, 200);
    const ovData = await ovRes.json();
    assert.ok(ovData.totalEvents >= 120);
    assert.equal(ovData.batteryPercent, 88);

    // 13. Import CSV Export (No-Membership Mode)
    const importRes = await fetch(`${baseUrl}/api/oura/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        filename: 'sleep.csv',
        content: 'day,readiness_score,sleep_score,lowest_heart_rate,average_hrv\n2026-10-19,91,89,49,74\n'
      })
    });
    assert.equal(importRes.status, 200);
    const importData = await importRes.json();
    assert.equal(importData.daysImported, 1);

    // 14. Test Oura Cycle Insights & Biphasic Temperature Ovulation Detection for Maya (userId = 2)
    const cycleRes = await fetch(`${baseUrl}/api/dashboard/cycle?userId=2&days=60`, {
      headers: { Cookie: cookie }
    });
    assert.equal(cycleRes.status, 200);
    const cycleData = await cycleRes.json();
    assert.equal(cycleData.hasCycleData, true);
    assert.ok(cycleData.currentCycle?.cycleDay >= 1);
    assert.equal(cycleData.currentCycle?.avgCycleLength, 28);
    assert.ok(cycleData.currentCycle?.fertileWindow?.thermalShiftDeltaC >= 0.18);
    assert.ok(cycleData.phaseComparison?.follicular?.tempDeviation < 0);
    assert.ok(cycleData.phaseComparison?.luteal?.tempDeviation > 0);
    assert.equal(cycleData.timeline.length, 60);

    // Log daily symptom & flow on `/api/cycle/log`
    const logCycleRes = await fetch(`${baseUrl}/api/cycle/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        userId: 2,
        day: cycleData.day,
        flow: 'spotting',
        symptoms: ['Cramps', 'Calm'],
        ovulationTest: 'none',
        notes: 'Tested cycle symptom logging'
      })
    });
    assert.equal(logCycleRes.status, 200);
    const logCycleJson = await logCycleRes.json();
    assert.equal(logCycleJson.cycle.selectedDayLog.flow, 'spotting');
    assert.deepEqual(logCycleJson.cycle.selectedDayLog.symptoms, ['Cramps', 'Calm']);

    console.log('✅ All 14 end-to-end open_oura BLE protocol, AES-128-ECB auth, binary event decoding, ecore scoring, Cycle Insights (biphasic temp shift), couple-sync, analytics, and security tests passed!');
  } finally {
    server.close();
    if (fs.existsSync(TEST_DATA_DIR)) {
      fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
    }
  }
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
