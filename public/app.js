import { handleStaticApi } from './static-backend.js?v=6';

const IS_GITHUB_PAGES = typeof window !== 'undefined' && window.location.hostname.endsWith('github.io');

const state = {
  session: null,
  activeTab: (window.location.hash.replace('#', '') || 'today'),
  selectedUserId: null,
  selectedDay: null,
  dailyData: null,
  coupleData: null,
  trendsData: null,
  trendsDays: 30,
  trendsMetric: 'readiness',
  coupleMetric: 'readiness',
  corrData: null,
  corrDays: 60,
  corrX: 'bedtime_hour',
  corrY: 'deep_sleep_minutes',
  ringOverview: null,
  bleStatus: '',
  showResetGuide: false,
  syncLogs: [],
  userSessions: [],
  authModeView: 'login',
  toast: null,
  loading: false
};

const PRESET_TAGS = ['Magnesium', 'Sauna', 'Morning sunlight', 'Workout', 'Late meal', 'Wine', 'Travel', 'Breathwork'];

function showToast(msg) {
  state.toast = msg;
  render();
  setTimeout(() => {
    if (state.toast === msg) {
      state.toast = null;
      render();
    }
  }, 3800);
}

async function api(path, options = {}) {
  if (IS_GITHUB_PAGES || state.useStaticBackend) {
    return handleStaticApi(path, options);
  }
  try {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options
    });
    const contentType = res.headers.get('content-type') || '';
    if ((res.status === 404 || res.status === 405) && !contentType.includes('application/json')) {
      state.useStaticBackend = true;
      return handleStaticApi(path, options);
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  } catch (err) {
    if (err instanceof TypeError) {
      state.useStaticBackend = true;
      return handleStaticApi(path, options);
    }
    throw err;
  }
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatDuration(sec) {
  if (!sec || sec <= 0) return '0h 0m';
  const hrs = Math.floor(sec / 3600);
  const mins = Math.round((sec % 3600) / 60);
  return hrs > 0 ? `${hrs}h ${mins}m` : `${mins}m`;
}

function formatClock(isoStr) {
  if (!isoStr) return '--:--';
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return '--:--';
  return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

function scoreColor(score) {
  if (!score) return '#64748b';
  if (score >= 85) return '#10b981';
  if (score >= 74) return '#6366f1';
  return '#f59e0b';
}

function scoreLabel(score) {
  if (!score) return 'No Data';
  if (score >= 85) return 'Optimal';
  if (score >= 74) return 'Good';
  return 'Pay Attention';
}

function shiftDay(dayStr, deltaDays) {
  const d = new Date(`${dayStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + deltaDays);
  return d.toISOString().slice(0, 10);
}

async function initApp() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .register('./sw.js?v=6')
      .then((reg) => reg.update().catch(() => {}))
      .catch(() => {});
  }

  const params = new URLSearchParams(window.location.search);
  if (params.get('oauth') === 'success') {
    showToast('Connected Oura Ring via OAuth2! Syncing 90-day history...');
    window.history.replaceState({}, '', '/#settings');
    state.activeTab = 'settings';
  } else if (params.get('oauth') === 'error') {
    showToast(`Oura OAuth error: ${params.get('reason') || 'Failed'}`);
    window.history.replaceState({}, '', '/#settings');
    state.activeTab = 'settings';
  }

  await refreshSession();
}

async function refreshSession() {
  state.session = await api('/api/auth/session');
  if (state.session.authenticated && state.session.user) {
    if (!state.selectedUserId) {
      state.selectedUserId = state.session.user.id;
    }
    await loadCurrentTabData();
  } else {
    render();
  }
}

async function loadCurrentTabData() {
  if (!state.session?.authenticated) return;
  try {
    if (state.activeTab === 'today') {
      const q = new URLSearchParams({ userId: state.selectedUserId });
      if (state.selectedDay) q.set('day', state.selectedDay);
      state.dailyData = await api(`/api/dashboard/daily?${q.toString()}`);
      if (!state.selectedDay && state.dailyData.day) {
        state.selectedDay = state.dailyData.day;
      }
    } else if (state.activeTab === 'couple') {
      const q = new URLSearchParams();
      if (state.selectedDay) q.set('day', state.selectedDay);
      state.coupleData = await api(`/api/dashboard/couple?${q.toString()}`);
      if (!state.selectedDay && state.coupleData.day) {
        state.selectedDay = state.coupleData.day;
      }
    } else if (state.activeTab === 'trends') {
      const q = new URLSearchParams({
        userId: state.selectedUserId,
        days: state.trendsDays
      });
      if (state.selectedDay) q.set('endDay', state.selectedDay);
      state.trendsData = await api(`/api/dashboard/trends?${q.toString()}`);
    } else if (state.activeTab === 'correlations') {
      const q = new URLSearchParams({
        userId: state.selectedUserId,
        days: state.corrDays,
        metricX: state.corrX,
        metricY: state.corrY
      });
      if (state.selectedDay) q.set('endDay', state.selectedDay);
      state.corrData = await api(`/api/dashboard/correlations?${q.toString()}`);
    } else if (state.activeTab === 'settings') {
      const [logsRes, sessRes, ringRes] = await Promise.all([
        api('/api/oura/logs'),
        api('/api/user/sessions'),
        api('/api/ring/overview')
      ]);
      state.syncLogs = logsRes.logs || [];
      state.userSessions = sessRes.sessions || [];
      state.ringOverview = ringRes;
    }
  } catch (err) {
    showToast(err.message);
  }
  render();
}

function setTab(tab) {
  state.activeTab = tab;
  window.location.hash = tab;
  loadCurrentTabData();
}

/* SVG Builders */
function renderScoreRingCard(title, score, baselineScore, contributors) {
  const color = scoreColor(score);
  const label = scoreLabel(score);
  const radius = 44;
  const circum = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score || 0));
  const dashOffset = (circum * (100 - pct)) / 100;
  const delta = score != null && baselineScore != null ? score - baselineScore : null;
  const deltaStr =
    delta == null ? '' : delta > 0 ? `+${delta} vs 30d avg` : delta < 0 ? `${delta} vs 30d avg` : `At 30d avg (${baselineScore})`;

  return `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">${escapeHtml(title)}</div>
          <div class="card-subtitle">${escapeHtml(label)} ${deltaStr ? `• ${escapeHtml(deltaStr)}` : ''}</div>
        </div>
      </div>
      <div class="score-ring-layout">
        <div class="ring-gauge-wrap">
          <svg width="106" height="106" viewBox="0 0 106 106">
            <circle cx="53" cy="53" r="${radius}" fill="none" stroke="rgba(148,163,184,0.14)" stroke-width="9" />
            <circle
              cx="53"
              cy="53"
              r="${radius}"
              fill="none"
              stroke="${color}"
              stroke-width="9"
              stroke-linecap="round"
              stroke-dasharray="${circum.toFixed(1)}"
              stroke-dashoffset="${dashOffset.toFixed(1)}"
              transform="rotate(-90 53 53)"
            />
          </svg>
          <div class="ring-gauge-center">
            <div class="ring-score-num">${score ?? '--'}</div>
            <div class="ring-score-tag">Score</div>
          </div>
        </div>
        <div class="contrib-list">
          ${contributors
            .map((c) => {
              const val = Math.max(0, Math.min(100, c.value ?? 0));
              const barColor = val >= 80 ? '#10b981' : val >= 68 ? '#6366f1' : '#f59e0b';
              return `
                <div class="contrib-row">
                  <div class="contrib-meta">
                    <span>${escapeHtml(c.label)}</span>
                    <strong>${c.display || `${val}`}</strong>
                  </div>
                  <div class="contrib-bar-bg">
                    <div class="contrib-bar-fill" style="width:${val}%;background:${barColor}"></div>
                  </div>
                </div>
              `;
            })
            .join('')}
        </div>
      </div>
    </div>
  `;
}

function renderNightCurveSvg(values, color, label, unit) {
  if (!Array.isArray(values) || values.length < 3) {
    return `<div style="color:var(--text-muted);font-size:0.84rem;padding:20px 0;">No 5-minute ${escapeHtml(label)} curve recorded for this night.</div>`;
  }
  const w = 560;
  const h = 155;
  const padX = 28;
  const padY = 20;
  const minVal = Math.min(...values);
  const maxVal = Math.max(...values);
  const avgVal = Math.round(values.reduce((a, b) => a + b, 0) / values.length);
  const span = Math.max(4, maxVal - minVal);

  const pts = values.map((v, idx) => {
    const x = padX + (idx / (values.length - 1)) * (w - padX * 2);
    const y = h - padY - ((v - minVal) / span) * (h - padY * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const areaPath = `M ${padX},${h - padY} L ${pts.join(' L ')} L ${w - padX},${h - padY} Z`;

  return `
    <div>
      <div style="display:flex;justify-content:space-between;font-size:0.78rem;color:var(--text-muted);margin-bottom:6px;">
        <span>Low: <strong style="color:var(--text-primary)">${minVal} ${unit}</strong></span>
        <span>Avg: <strong style="color:var(--text-primary)">${avgVal} ${unit}</strong></span>
        <span>Peak: <strong style="color:var(--text-primary)">${maxVal} ${unit}</strong></span>
      </div>
      <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:155px;overflow:visible;">
        <defs>
          <linearGradient id="grad-${label.replace(/\s+/g, '')}" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="${color}" stop-opacity="0.38"/>
            <stop offset="100%" stop-color="${color}" stop-opacity="0.0"/>
          </linearGradient>
        </defs>
        <path d="${areaPath}" fill="url(#grad-${label.replace(/\s+/g, '')})" />
        <polyline fill="none" stroke="${color}" stroke-width="2.4" points="${pts.join(' ')}" />
      </svg>
    </div>
  `;
}

function render24hHeartrateSvg(samples) {
  if (!Array.isArray(samples) || samples.length < 4) {
    return `<div style="color:var(--text-muted);font-size:0.84rem;padding:18px 0;">Intraday 24-hour heart rate points are available for recent synced days.</div>`;
  }
  const w = 680;
  const h = 165;
  const padX = 30;
  const padY = 20;
  const bpms = samples.map((s) => s.bpm);
  const minBpm = Math.min(...bpms);
  const maxBpm = Math.max(...bpms);
  const avgBpm = Math.round(bpms.reduce((a, b) => a + b, 0) / bpms.length);
  const span = Math.max(10, maxBpm - minBpm);

  const pts = samples.map((s, i) => {
    const x = padX + (i / (samples.length - 1)) * (w - padX * 2);
    const y = h - padY - ((s.bpm - minBpm) / span) * (h - padY * 2);
    return { x, y, bpm: s.bpm, source: s.source };
  });

  const lineStr = pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const sourceColor = (src) =>
    src === 'workout' ? '#f59e0b' : src === 'sleep' ? '#8b5cf6' : src === 'rest' ? '#10b981' : '#ef4444';

  return `
    <div>
      <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;font-size:0.78rem;color:var(--text-muted);margin-bottom:8px;">
        <span>Min: <strong style="color:#f8fafc">${minBpm} bpm</strong> • Avg: <strong style="color:#f8fafc">${avgBpm} bpm</strong> • Max: <strong style="color:#f8fafc">${maxBpm} bpm</strong></span>
        <span style="display:flex;gap:12px;">
          <span style="color:#8b5cf6">● Sleep</span>
          <span style="color:#10b981">● Rest</span>
          <span style="color:#ef4444">● Awake</span>
          <span style="color:#f59e0b">● Workout</span>
        </span>
      </div>
      <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:165px;">
        <polyline fill="none" stroke="rgba(239, 68, 68, 0.55)" stroke-width="2" points="${lineStr}" />
        ${pts
          .filter((_, idx) => idx % 2 === 0)
          .map(
            (p) =>
              `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.8" fill="${sourceColor(p.source)}" />`
          )
          .join('')}
      </svg>
      <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:var(--text-muted);padding:0 12px;">
        <span>00:00</span>
        <span>06:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>23:45</span>
      </div>
    </div>
  `;
}

/* Views */
function renderAuthView() {
  const members = state.session?.householdMembers || [];
  const regLocked = state.session?.registrationLocked;
  const showSetupHint = Boolean(state.session?.showFirstTimeSetupHint);

  return `
    <div class="auth-wrapper">
      <div class="auth-card">
        <div class="brand-header">
          <img src="./icon.svg" alt="Laura" class="brand-logo" />
          <div>
            <div class="brand-title">Laura</div>
            <div class="brand-subtitle">Private Oura Ring 3 Household Hub</div>
          </div>
        </div>

        ${
          members.length > 0
            ? `
          <div class="quick-demo-box">
            <div class="quick-demo-label">Select Household Member (Password Required)</div>
            <div class="quick-demo-buttons">
              ${members
                .slice(0, 3)
                .map(
                  (m) => `
                <button type="button" class="btn" data-select-login-user="${escapeHtml(m.username)}" style="justify-content:flex-start;">
                  <span class="avatar-dot" style="background:${escapeHtml(m.avatarColor)}"></span>
                  <span>${escapeHtml(m.displayName)} <small style="color:var(--text-muted);">(@${escapeHtml(m.username)})</small></span>
                </button>
              `
                )
                .join('')}
            </div>
          </div>
        `
            : ''
        }

        ${
          state.authModeView === 'login'
            ? `
          <form id="login-form">
            <div class="form-group">
              <label class="form-label">Username</label>
              <input class="form-input" id="login-username-input" name="username" placeholder="Enter your username" required autocomplete="username" />
            </div>
            <div class="form-group">
              <label class="form-label">Password</label>
              <input class="form-input" id="login-password-input" type="password" name="password" placeholder="••••••••" required autocomplete="current-password" />
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;padding:11px;margin-top:4px;">
              🔒 Sign In to Dashboard
            </button>
          </form>

          ${
            showSetupHint
              ? `
            <div style="margin-top:12px;padding:10px 12px;border-radius:10px;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.28);font-size:0.76rem;color:var(--text-secondary);">
              <strong>First-Time Setup:</strong> Initial bootstrap password for <code>alex</code> / <code>maya</code> is <code>laura2026</code>. Sign in and set your permanent household usernames & passwords in <strong>Settings → Security Layers</strong> (this notice disappears once updated).
            </div>
          `
              : ''
          }

          <div style="margin-top:14px;font-size:0.75rem;color:var(--text-muted);text-align:center;">
            🛡️ Passwords hashed with <strong>PBKDF2-HMAC-SHA256 (210,000 iterations + 16B salt)</strong> • Max 3 household users
          </div>

          <div style="margin-top:10px;font-size:0.8rem;color:var(--text-muted);text-align:center;">
            ${
              regLocked
                ? '🔒 Registration is locked to household members (manageable by Admin in Settings).'
                : `<a href="#" id="toggle-register" style="color:#a5b4fc;">Add household account (up to 3 max) →</a>`
            }
          </div>
        `
            : `
          <form id="register-form">
            <div class="form-group">
              <label class="form-label">Username</label>
              <input class="form-input" name="username" placeholder="e.g. satya" required />
            </div>
            <div class="form-group">
              <label class="form-label">Display Name</label>
              <input class="form-input" name="displayName" placeholder="e.g. Satya" required />
            </div>
            <div class="form-group">
              <label class="form-label">Ring Model / Name</label>
              <input class="form-input" name="ringName" value="Oura Ring Gen 3" />
            </div>
            <div class="form-group">
              <label class="form-label">Password (8+ chars)</label>
              <input class="form-input" type="password" name="password" minlength="8" required />
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;padding:11px;">
              Create Household Account
            </button>
          </form>
          <div style="margin-top:14px;text-align:center;font-size:0.82rem;">
            <a href="#" id="toggle-login" style="color:#a5b4fc;">← Back to Sign In</a>
          </div>
        `
        }
      </div>
    </div>
  `;
}

function renderTodayView() {
  const d = state.dailyData;
  if (!d || !d.summary) {
    return `<div class="card"><p>No Oura Ring summary found for ${escapeHtml(state.selectedDay || 'this date')}. Try selecting another date or syncing your ring.</p></div>`;
  }

  const s = d.summary;
  const b = d.baseline || {};
  const rScore = s.readiness?.score;
  const slScore = s.sleep?.score;
  const actScore = s.activity?.score;

  const rhrDelta =
    s.sleep?.lowestHr != null && b.lowestHr != null ? Number((s.sleep.lowestHr - b.lowestHr).toFixed(1)) : null;
  const hrvDelta =
    s.sleep?.averageHrv != null && b.averageHrv != null ? Math.round(s.sleep.averageHrv - b.averageHrv) : null;

  const totalSl = Math.max(1, s.sleep?.totalSeconds || 1);
  const deepPct = Math.round(((s.sleep?.deepSeconds || 0) / totalSl) * 100);
  const remPct = Math.round(((s.sleep?.remSeconds || 0) / totalSl) * 100);
  const lightPct = Math.max(0, 100 - deepPct - remPct);

  const hypnoChars = (s.sleep?.hypnogram5min || '').split('');

  return `
    <!-- 3 Primary Oura Score Cards -->
    <div class="grid-3">
      ${renderScoreRingCard('Readiness', rScore, b.readiness, [
        { label: 'HRV Balance', value: s.readiness?.contributors?.hrvBalance },
        { label: 'Resting Heart Rate', value: s.readiness?.contributors?.restingHeartRate },
        { label: 'Sleep Balance', value: s.readiness?.contributors?.sleepBalance },
        { label: 'Recovery Index', value: s.readiness?.contributors?.recoveryIndex }
      ])}
      ${renderScoreRingCard('Sleep', slScore, b.sleep, [
        {
          label: 'Total Sleep',
          value: Math.min(100, Math.round(((s.sleep?.totalSeconds || 0) / 28800) * 100)),
          display: formatDuration(s.sleep?.totalSeconds)
        },
        {
          label: 'Deep Sleep',
          value: Math.min(100, Math.round(((s.sleep?.deepSeconds || 0) / 5400) * 100)),
          display: `${formatDuration(s.sleep?.deepSeconds)} (${deepPct}%)`
        },
        {
          label: 'REM Sleep',
          value: Math.min(100, Math.round(((s.sleep?.remSeconds || 0) / 6000) * 100)),
          display: `${formatDuration(s.sleep?.remSeconds)} (${remPct}%)`
        },
        {
          label: 'Sleep Efficiency',
          value: s.sleep?.efficiency || 0,
          display: `${s.sleep?.efficiency ?? '--'}%`
        }
      ])}
      ${renderScoreRingCard('Activity', actScore, b.activity, [
        {
          label: 'Steps',
          value: Math.min(100, Math.round(((s.activity?.steps || 0) / 10000) * 100)),
          display: (s.activity?.steps || 0).toLocaleString()
        },
        {
          label: 'Active Calories',
          value: Math.min(100, Math.round(((s.activity?.activeCalories || 0) / 550) * 100)),
          display: `${s.activity?.activeCalories || 0} kcal`
        },
        {
          label: 'Walking Distance',
          value: Math.min(100, Math.round(((s.activity?.walkingDistanceMeters || 0) / 8000) * 100)),
          display: `${((s.activity?.walkingDistanceMeters || 0) / 1000).toFixed(1)} km`
        },
        {
          label: 'Activity Balance',
          value: s.readiness?.contributors?.activityBalance || 80
        }
      ])}
    </div>

    <!-- 6 Biometric Vitals Grid -->
    <div class="vitals-grid">
      <div class="vital-card">
        <div class="vital-label">Lowest Resting HR</div>
        <div class="vital-value">${s.sleep?.lowestHr ?? '--'} <span class="vital-unit">bpm</span></div>
        <div class="vital-delta ${rhrDelta != null && rhrDelta <= 0 ? 'delta-good' : 'delta-warn'}">
          ${rhrDelta != null ? `${rhrDelta > 0 ? '+' : ''}${rhrDelta} bpm vs 30d (${b.lowestHr})` : '30d baseline'}
        </div>
      </div>

      <div class="vital-card">
        <div class="vital-label">Nighttime HRV</div>
        <div class="vital-value">${s.sleep?.averageHrv ?? '--'} <span class="vital-unit">ms</span></div>
        <div class="vital-delta ${hrvDelta != null && hrvDelta >= 0 ? 'delta-good' : 'delta-warn'}">
          ${hrvDelta != null ? `${hrvDelta > 0 ? '+' : ''}${hrvDelta} ms vs 30d (${b.averageHrv})` : '30d baseline'}
        </div>
      </div>

      <div class="vital-card">
        <div class="vital-label">Body Temp Deviation</div>
        <div class="vital-value">
          ${s.readiness?.tempDeviation != null ? `${s.readiness.tempDeviation > 0 ? '+' : ''}${s.readiness.tempDeviation}` : '--'}
          <span class="vital-unit">°C</span>
        </div>
        <div class="vital-delta ${Math.abs(s.readiness?.tempDeviation || 0) <= 0.2 ? 'delta-good' : 'delta-warn'}">
          ${Math.abs(s.readiness?.tempDeviation || 0) <= 0.2 ? 'Within normal range' : 'Elevated shift'}
        </div>
      </div>

      <div class="vital-card">
        <div class="vital-label">Blood Oxygen (SpO2)</div>
        <div class="vital-value">${s.spo2?.percentage ?? '--'} <span class="vital-unit">%</span></div>
        <div class="vital-delta delta-good">
          Breathing regularity: ${(s.spo2?.breathingDisturbanceIndex ?? 0) < 1.5 ? 'Optimal' : 'Check'}
        </div>
      </div>

      <div class="vital-card">
        <div class="vital-label">Daytime Stress / Recovery</div>
        <div class="vital-value">
          ${Math.round((s.stress?.stressHighSeconds || 0) / 60)}m
          <span class="vital-unit">/ ${Math.round((s.stress?.recoveryHighSeconds || 0) / 60)}m rec</span>
        </div>
        <div class="vital-delta ${s.stress?.daySummary === 'restored' ? 'delta-good' : 'delta-neutral'}">
          Day summary: ${escapeHtml(s.stress?.daySummary || 'balanced')}
        </div>
      </div>

      <div class="vital-card">
        <div class="vital-label">Respiratory Rate</div>
        <div class="vital-value">${s.sleep?.averageBreath ?? '--'} <span class="vital-unit">br/min</span></div>
        <div class="vital-delta delta-neutral">
          Latency: ${Math.round((s.sleep?.latencySeconds || 0) / 60)} min to fall asleep
        </div>
      </div>
    </div>

    <!-- Sleep Stage Hypnogram & Architecture -->
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header">
        <div>
          <div class="card-title">Sleep Stage Hypnogram & Window</div>
          <div class="card-subtitle">
            Bedtime ${formatClock(s.sleep?.bedtimeStart)} → Wake ${formatClock(s.sleep?.bedtimeEnd)}
            • Time in Bed: ${formatDuration(s.sleep?.timeInBedSeconds)} • Asleep: ${formatDuration(s.sleep?.totalSeconds)}
          </div>
        </div>
      </div>

      ${
        hypnoChars.length > 0
          ? `
        <div class="hypnogram-bars">
          ${hypnoChars.map((ch) => `<div class="hypno-slice hypno-stage-${escapeHtml(ch)}"></div>`).join('')}
        </div>
        <div style="display:flex;justify-content:space-between;font-size:0.74rem;color:var(--text-muted);">
          <span>${formatClock(s.sleep?.bedtimeStart)}</span>
          <span>Mid-Sleep</span>
          <span>${formatClock(s.sleep?.bedtimeEnd)}</span>
        </div>
      `
          : `<p style="color:var(--text-muted);font-size:0.84rem;">No 5-min hypnogram string recorded.</p>`
      }

      <div class="hypno-legend">
        <div class="stage-pill">
          <div style="color:#f59e0b;font-weight:700;">● Awake</div>
          <div>${formatDuration(s.sleep?.awakeSeconds)}</div>
        </div>
        <div class="stage-pill">
          <div style="color:#06b6d4;font-weight:700;">● REM (${remPct}%)</div>
          <div>${formatDuration(s.sleep?.remSeconds)}</div>
        </div>
        <div class="stage-pill">
          <div style="color:#6366f1;font-weight:700;">● Light (${lightPct}%)</div>
          <div>${formatDuration(s.sleep?.lightSeconds)}</div>
        </div>
        <div class="stage-pill">
          <div style="color:#8b5cf6;font-weight:700;">● Deep (${deepPct}%)</div>
          <div>${formatDuration(s.sleep?.deepSeconds)}</div>
        </div>
      </div>
    </div>

    <!-- Nighttime HR & HRV Curves -->
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Nighttime Heart Rate Curve</div>
            <div class="card-subtitle">5-minute intervals during sleep</div>
          </div>
        </div>
        ${renderNightCurveSvg(s.sleep?.hr5min, '#ec4899', 'Sleep HR', 'bpm')}
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Nighttime HRV Curve (rMSSD)</div>
            <div class="card-subtitle">5-minute heart rate variability trend</div>
          </div>
        </div>
        ${renderNightCurveSvg(s.sleep?.hrv5min, '#6366f1', 'Sleep HRV', 'ms')}
      </div>
    </div>

    <!-- 24-Hour Intraday Heart Rate -->
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header">
        <div>
          <div class="card-title">24-Hour Intraday Heart Rate & Workouts</div>
          <div class="card-subtitle">Daytime, rest, workout, and sleep heart rate samples</div>
        </div>
      </div>
      ${render24hHeartrateSvg(d.heartrate)}
      ${
        (d.workouts || []).length > 0
          ? `
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border-subtle);display:flex;gap:10px;flex-wrap:wrap;">
          ${d.workouts
            .map(
              (w) => `
            <span class="tag-chip" style="background:rgba(16,185,129,0.14);border-color:rgba(16,185,129,0.35);color:#6ee7b7;">
              🏃 ${escapeHtml(w.activity)} • ${w.calories} kcal • ${escapeHtml(w.intensity)}
            </span>
          `
            )
            .join('')}
        </div>
      `
          : ''
      }
    </div>

    <!-- Daily Tags & Personal Journal Note -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Lifestyle Tags & Daily Note</div>
          <div class="card-subtitle">Tags automatically feed into your Tag Impact & Correlation analytics</div>
        </div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
        ${PRESET_TAGS.map((tag) => {
          const active = (s.tags || []).includes(tag);
          return `
            <button type="button" class="tag-chip ${active ? '' : 'inactive'}" data-toggle-tag="${escapeHtml(tag)}">
              ${active ? '✓' : '+'} ${escapeHtml(tag)}
            </button>
          `;
        }).join('')}
      </div>
      <form id="daily-note-form" style="display:flex;gap:10px;flex-wrap:wrap;">
        <input
          class="form-input"
          name="customNote"
          value="${escapeHtml(s.customNote || '')}"
          placeholder="Add a note for this day (e.g. Evening sauna, travel, felt energized)..."
          style="flex:1;min-width:240px;"
        />
        <button type="submit" class="btn btn-primary">Save Note</button>
      </form>
    </div>
  `;
}

function renderCoupleView() {
  const c = state.coupleData;
  if (!c || !c.members) {
    return `<div class="card"><p>Loading Household Couple Sync...</p></div>`;
  }

  const members = c.members;
  const ov = c.sleepOverlap;

  // Dual 14-day comparison chart
  let dualChartHtml = '';
  if (members.length >= 2) {
    const [m1, m2] = members;
    const w = 680;
    const h = 185;
    const padX = 32;
    const padY = 24;
    const metric = state.coupleMetric;

    const extractVal = (s) => {
      if (!s) return null;
      if (metric === 'readiness') return s.readiness?.score;
      if (metric === 'sleep') return s.sleep?.score;
      if (metric === 'hrv') return s.sleep?.averageHrv;
      if (metric === 'rhr') return s.sleep?.lowestHr;
      return s.readiness?.score;
    };

    const daysList = m1.series14.map((d) => d.day);
    const map2 = new Map(m2.series14.map((d) => [d.day, d]));
    const vals1 = m1.series14.map(extractVal);
    const vals2 = daysList.map((day) => extractVal(map2.get(day)));
    const allNums = [...vals1, ...vals2].filter((v) => v != null);
    const minV = allNums.length ? Math.min(...allNums) - 4 : 40;
    const maxV = allNums.length ? Math.max(...allNums) + 4 : 100;
    const span = Math.max(8, maxV - minV);

    const buildPts = (arr) =>
      arr
        .map((v, idx) => {
          if (v == null) return null;
          const x = padX + (idx / Math.max(1, arr.length - 1)) * (w - padX * 2);
          const y = h - padY - ((v - minV) / span) * (h - padY * 2);
          return `${x.toFixed(1)},${y.toFixed(1)}`;
        })
        .filter(Boolean)
        .join(' ');

    dualChartHtml = `
      <div class="card">
        <div class="card-header" style="flex-wrap:wrap;">
          <div>
            <div class="card-title">14-Day Partner Trajectory Overlay</div>
            <div class="card-subtitle">Compare ${escapeHtml(m1.user.displayName)} vs ${escapeHtml(m2.user.displayName)} over the past 2 weeks</div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            ${[
              { k: 'readiness', label: 'Readiness' },
              { k: 'sleep', label: 'Sleep Score' },
              { k: 'hrv', label: 'HRV (ms)' },
              { k: 'rhr', label: 'Resting HR' }
            ]
              .map(
                (item) => `
              <button class="btn ${state.coupleMetric === item.k ? 'btn-primary' : ''}" data-couple-metric="${item.k}" style="padding:5px 10px;font-size:0.78rem;">
                ${item.label}
              </button>
            `
              )
              .join('')}
          </div>
        </div>
        <div style="display:flex;gap:18px;font-size:0.8rem;margin-bottom:8px;">
          <span><strong style="color:${escapeHtml(m1.user.avatarColor)}">● ${escapeHtml(m1.user.displayName)}</strong></span>
          <span><strong style="color:${escapeHtml(m2.user.avatarColor)}">● ${escapeHtml(m2.user.displayName)}</strong></span>
        </div>
        <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:185px;">
          <polyline fill="none" stroke="${escapeHtml(m1.user.avatarColor)}" stroke-width="3" points="${buildPts(vals1)}" />
          <polyline fill="none" stroke="${escapeHtml(m2.user.avatarColor)}" stroke-width="3" points="${buildPts(vals2)}" />
        </svg>
        <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:var(--text-muted);padding:0 16px;">
          <span>${escapeHtml(daysList[0] || '')}</span>
          <span>${escapeHtml(daysList[Math.floor(daysList.length / 2)] || '')}</span>
          <span>${escapeHtml(daysList[daysList.length - 1] || '')}</span>
        </div>
      </div>
    `;
  }

  return `
    <!-- Couple Recovery Briefing Banner -->
    <div class="couple-banner">
      <h2>💑 ${escapeHtml(c.briefing?.headline || 'Couple Recovery Sync')}</h2>
      <p>${escapeHtml(c.briefing?.detail || '')}</p>
      <div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:12px;font-size:0.8rem;">
        <span class="tag-chip">🔥 Shared Readiness ≥75 Streak: <strong>${c.sharedStreaks?.readiness75 || 0} days</strong></span>
        <span class="tag-chip">🌙 Shared Sleep ≥75 Streak: <strong>${c.sharedStreaks?.sleep75 || 0} days</strong></span>
        <span class="tag-chip">👟 Shared 7.5k+ Steps Streak: <strong>${c.sharedStreaks?.steps8k || 0} days</strong></span>
      </div>
    </div>

    <!-- Side-by-Side Member Comparison Cards -->
    <div class="grid-2">
      ${members
        .map((m) => {
          const s = m.summary || {};
          const b = m.baseline || {};
          return `
            <div class="card" style="border-top: 3px solid ${escapeHtml(m.user.avatarColor)};">
              <div class="card-header">
                <div>
                  <div class="card-title">
                    <span class="avatar-dot" style="background:${escapeHtml(m.user.avatarColor)}"></span>
                    ${escapeHtml(m.user.displayName)}
                  </div>
                  <div class="card-subtitle">${escapeHtml(m.user.ringName)} • ${escapeHtml(m.recoveryStatus)}</div>
                </div>
              </div>

              <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;text-align:center;margin-bottom:14px;">
                <div style="background:rgba(15,23,42,0.7);padding:12px 8px;border-radius:10px;">
                  <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;">Readiness</div>
                  <div style="font-size:1.55rem;font-weight:800;color:${scoreColor(s.readiness?.score)}">${s.readiness?.score ?? '--'}</div>
                  <div style="font-size:0.7rem;color:var(--text-muted);">30d avg: ${b.readiness}</div>
                </div>
                <div style="background:rgba(15,23,42,0.7);padding:12px 8px;border-radius:10px;">
                  <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;">Sleep</div>
                  <div style="font-size:1.55rem;font-weight:800;color:${scoreColor(s.sleep?.score)}">${s.sleep?.score ?? '--'}</div>
                  <div style="font-size:0.7rem;color:var(--text-muted);">${formatDuration(s.sleep?.totalSeconds)}</div>
                </div>
                <div style="background:rgba(15,23,42,0.7);padding:12px 8px;border-radius:10px;">
                  <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;">Activity</div>
                  <div style="font-size:1.55rem;font-weight:800;color:${scoreColor(s.activity?.score)}">${s.activity?.score ?? '--'}</div>
                  <div style="font-size:0.7rem;color:var(--text-muted);">${(s.activity?.steps || 0).toLocaleString()} steps</div>
                </div>
              </div>

              <table class="table-clean">
                <tbody>
                  <tr>
                    <td>Lowest Resting HR</td>
                    <td><strong>${s.sleep?.lowestHr ?? '--'} bpm</strong></td>
                    <td style="text-align:right;color:var(--text-muted);">
                      ${m.deltas?.rhrDelta != null ? `${m.deltas.rhrDelta > 0 ? '+' : ''}${m.deltas.rhrDelta} vs 30d (${b.lowestHr})` : ''}
                    </td>
                  </tr>
                  <tr>
                    <td>Nighttime HRV</td>
                    <td><strong>${s.sleep?.averageHrv ?? '--'} ms</strong></td>
                    <td style="text-align:right;color:var(--text-muted);">
                      ${m.deltas?.hrvDelta != null ? `${m.deltas.hrvDelta > 0 ? '+' : ''}${m.deltas.hrvDelta} vs 30d (${b.averageHrv})` : ''}
                    </td>
                  </tr>
                  <tr>
                    <td>Deep & REM Sleep</td>
                    <td><strong>${formatDuration(s.sleep?.deepSeconds)} deep</strong></td>
                    <td style="text-align:right;color:var(--text-muted);">${formatDuration(s.sleep?.remSeconds)} REM</td>
                  </tr>
                  <tr>
                    <td>Sleep Window</td>
                    <td><strong>${formatClock(s.sleep?.bedtimeStart)} → ${formatClock(s.sleep?.bedtimeEnd)}</strong></td>
                    <td style="text-align:right;color:var(--text-muted);">${s.sleep?.efficiency ?? '--'}% eff</td>
                  </tr>
                  <tr>
                    <td>Daytime Stress / SpO2</td>
                    <td><strong>${Math.round((s.stress?.stressHighSeconds || 0) / 60)}m stress</strong></td>
                    <td style="text-align:right;color:var(--text-muted);">SpO2 ${s.spo2?.percentage ?? '--'}%</td>
                  </tr>
                </tbody>
              </table>
            </div>
          `;
        })
        .join('')}
    </div>

    <!-- Sleep Schedule Overlap Card -->
    ${
      ov
        ? `
      <div class="card" style="margin-bottom:18px;">
        <div class="card-header">
          <div>
            <div class="card-title">Bedtime & Sleep Schedule Overlap</div>
            <div class="card-subtitle">
              ${ov.overlapHours} hrs overlapping sleep (${ov.overlapPercent}% sync) • Bedtime within ${ov.bedtimeDiffMinutes} mins • Wake within ${ov.wakeDiffMinutes} mins
            </div>
          </div>
        </div>
        <div class="overlap-track">
          <div class="overlap-bar" style="left:${ov.member1.offsetStartPct}%;width:${ov.member1.widthPct}%;background:rgba(99,102,241,0.82);">
            ${escapeHtml(ov.member1.name)}: ${formatClock(ov.member1.bedtimeStart)} – ${formatClock(ov.member1.bedtimeEnd)}
          </div>
        </div>
        <div class="overlap-track">
          <div class="overlap-bar" style="left:${ov.member2.offsetStartPct}%;width:${ov.member2.widthPct}%;background:rgba(236,72,153,0.82);">
            ${escapeHtml(ov.member2.name)}: ${formatClock(ov.member2.bedtimeStart)} – ${formatClock(ov.member2.bedtimeEnd)}
          </div>
        </div>
      </div>
    `
        : ''
    }

    ${dualChartHtml}
  `;
}

function renderTrendsView() {
  const t = state.trendsData;
  if (!t || !t.series) {
    return `<div class="card"><p>Loading Long-Term Trends...</p></div>`;
  }

  const metricDefs = {
    readiness: { label: 'Readiness Score', unit: 'pts', color: '#6366f1', get: (d) => d.readiness?.score },
    sleep: { label: 'Sleep Score', unit: 'pts', color: '#8b5cf6', get: (d) => d.sleep?.score },
    hrv: { label: 'Nighttime HRV', unit: 'ms', color: '#10b981', get: (d) => d.sleep?.averageHrv },
    rhr: { label: 'Lowest Resting HR', unit: 'bpm', color: '#ec4899', get: (d) => d.sleep?.lowestHr },
    deep: { label: 'Deep Sleep', unit: 'min', color: '#06b6d4', get: (d) => (d.sleep?.deepSeconds ? Math.round(d.sleep.deepSeconds / 60) : null) },
    steps: { label: 'Daily Steps', unit: 'steps', color: '#f59e0b', get: (d) => d.activity?.steps }
  };

  const def = metricDefs[state.trendsMetric] || metricDefs.readiness;
  const series = t.series;
  const values = series.map(def.get);
  const validVals = values.filter((v) => v != null);
  const minVal = validVals.length ? Math.min(...validVals) : 0;
  const maxVal = validVals.length ? Math.max(...validVals) : 100;
  const avgVal = validVals.length ? (validVals.reduce((a, b) => a + b, 0) / validVals.length).toFixed(1) : '--';
  const span = Math.max(5, maxVal - minVal);

  // Compute 7-day rolling average
  const rolling7 = values.map((_, idx) => {
    const slice = values.slice(Math.max(0, idx - 6), idx + 1).filter((v) => v != null);
    if (!slice.length) return null;
    return slice.reduce((a, b) => a + b, 0) / slice.length;
  });

  const w = 720;
  const h = 210;
  const padX = 34;
  const padY = 24;

  const ptsDaily = values
    .map((v, i) => {
      if (v == null) return null;
      const x = padX + (i / Math.max(1, values.length - 1)) * (w - padX * 2);
      const y = h - padY - ((v - minVal) / span) * (h - padY * 2);
      return { x, y, v, day: series[i].day };
    })
    .filter(Boolean);

  const ptsRolling = rolling7
    .map((v, i) => {
      if (v == null) return null;
      const x = padX + (i / Math.max(1, rolling7.length - 1)) * (w - padX * 2);
      const y = h - padY - ((v - minVal) / span) * (h - padY * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .filter(Boolean)
    .join(' ');

  return `
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header" style="flex-wrap:wrap;">
        <div>
          <div class="card-title">${escapeHtml(def.label)} — Rolling Baseline & Daily Trend</div>
          <div class="card-subtitle">
            Window Average: <strong>${avgVal} ${def.unit}</strong> • Min: ${minVal} ${def.unit} • Max: ${maxVal} ${def.unit}
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${[14, 30, 90]
            .map(
              (d) => `
            <button class="btn ${state.trendsDays === d ? 'btn-primary' : ''}" data-trends-days="${d}" style="padding:6px 11px;font-size:0.8rem;">
              ${d} Days
            </button>
          `
            )
            .join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
        ${Object.entries(metricDefs)
          .map(
            ([k, m]) => `
          <button class="btn ${state.trendsMetric === k ? 'btn-primary' : ''}" data-trends-metric="${k}" style="padding:6px 12px;font-size:0.8rem;">
            ${escapeHtml(m.label)}
          </button>
        `
          )
          .join('')}
      </div>

      <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:210px;">
        ${ptsDaily
          .map(
            (p) => `
          <line x1="${p.x.toFixed(1)}" y1="${h - padY}" x2="${p.x.toFixed(1)}" y2="${p.y.toFixed(1)}" stroke="${def.color}" stroke-opacity="0.28" stroke-width="${Math.max(2, Math.floor(420 / values.length))}" />
          <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3" fill="${def.color}" opacity="0.65" />
        `
          )
          .join('')}
        <polyline fill="none" stroke="#f8fafc" stroke-width="2.8" points="${ptsRolling}" />
      </svg>
      <div style="display:flex;justify-content:space-between;font-size:0.74rem;color:var(--text-muted);padding:0 16px;">
        <span>${escapeHtml(t.startDay)}</span>
        <span style="color:#f8fafc;">— White Line: 7-Day Rolling Baseline</span>
        <span>${escapeHtml(t.endDay)}</span>
      </div>
    </div>

    <!-- Lifestyle Tag Impact Analyzer -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Lifestyle Tag Impact Analysis (Last 90 Days)</div>
          <div class="card-subtitle">How logged habits & tags shift your next-night HRV, Resting HR, Deep Sleep, and Sleep Score vs your personal average</div>
        </div>
      </div>
      ${
        (t.tagImpacts || []).length > 0
          ? `
        <table class="table-clean">
          <thead>
            <tr>
              <th>Tag / Habit</th>
              <th>Nights Logged</th>
              <th>HRV Shift</th>
              <th>Resting HR Shift</th>
              <th>Deep Sleep Shift</th>
              <th>Sleep Score Shift</th>
            </tr>
          </thead>
          <tbody>
            ${t.tagImpacts
              .map(
                (row) => `
              <tr>
                <td><span class="tag-chip">${escapeHtml(row.tag)}</span></td>
                <td>${row.count} nights</td>
                <td class="${row.hrvDelta >= 0 ? 'delta-good' : 'delta-warn'}">
                  <strong>${row.hrvDelta > 0 ? '+' : ''}${row.hrvDelta} ms</strong>
                </td>
                <td class="${row.rhrDelta <= 0 ? 'delta-good' : 'delta-warn'}">
                  <strong>${row.rhrDelta > 0 ? '+' : ''}${row.rhrDelta} bpm</strong>
                </td>
                <td class="${row.deepMinutesDelta >= 0 ? 'delta-good' : 'delta-warn'}">
                  <strong>${row.deepMinutesDelta > 0 ? '+' : ''}${row.deepMinutesDelta} min</strong>
                </td>
                <td class="${row.sleepScoreDelta >= 0 ? 'delta-good' : 'delta-warn'}">
                  <strong>${row.sleepScoreDelta > 0 ? '+' : ''}${row.sleepScoreDelta} pts</strong>
                </td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      `
          : `<p style="color:var(--text-muted);font-size:0.85rem;">Add lifestyle tags on the Today tab to see automatic correlation impacts.</p>`
      }
    </div>
  `;
}

function renderCorrelationsView() {
  const c = state.corrData;
  if (!c) {
    return `<div class="card"><p>Loading Correlations Explorer...</p></div>`;
  }

  const pts = c.points || [];
  const w = 680;
  const h = 260;
  const padX = 44;
  const padY = 28;

  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const minX = xs.length ? Math.min(...xs) : 0;
  const maxX = xs.length ? Math.max(...xs) : 1;
  const minY = ys.length ? Math.min(...ys) : 0;
  const maxY = ys.length ? Math.max(...ys) : 1;
  const spanX = Math.max(0.1, maxX - minX);
  const spanY = Math.max(0.1, maxY - minY);

  const mapX = (x) => padX + ((x - minX) / spanX) * (w - padX * 2);
  const mapY = (y) => h - padY - ((y - minY) / spanY) * (h - padY * 2);

  const regY1 = c.slope * minX + c.intercept;
  const regY2 = c.slope * maxX + c.intercept;

  const presets = [
    { label: 'Bedtime vs. Deep Sleep', x: 'bedtime_hour', y: 'deep_sleep_minutes' },
    { label: 'Bedtime vs. Nighttime HRV', x: 'bedtime_hour', y: 'average_hrv' },
    { label: 'Resting HR vs. Nighttime HRV', x: 'lowest_hr', y: 'average_hrv' },
    { label: 'Total Sleep vs. Readiness', x: 'total_sleep_hours', y: 'readiness_score' },
    { label: 'Daytime Stress vs. Sleep Score', x: 'stress_minutes', y: 'sleep_score' }
  ];

  return `
    <div class="card">
      <div class="card-header" style="flex-wrap:wrap;">
        <div>
          <div class="card-title">Biometric Scatter & Correlation Explorer</div>
          <div class="card-subtitle">
            Pearson <strong>r = ${c.pearsonR}</strong> (${escapeHtml(c.strength)}) across ${pts.length} nights
          </div>
        </div>
        <div style="display:flex;gap:6px;">
          ${[30, 60, 90]
            .map(
              (d) => `
            <button class="btn ${state.corrDays === d ? 'btn-primary' : ''}" data-corr-days="${d}" style="padding:5px 10px;font-size:0.78rem;">
              ${d}d
            </button>
          `
            )
            .join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
        ${presets
          .map(
            (p) => `
          <button
            class="tag-chip ${state.corrX === p.x && state.corrY === p.y ? '' : 'inactive'}"
            data-corr-preset="${p.x}:${p.y}"
          >
            ${escapeHtml(p.label)}
          </button>
        `
          )
          .join('')}
      </div>

      <div class="grid-2" style="margin-bottom:14px;">
        <div>
          <label class="form-label">X-Axis Metric</label>
          <select id="corr-select-x" class="form-select">
            ${(c.availableMetrics || [])
              .map(
                (m) => `
              <option value="${escapeHtml(m.key)}" ${m.key === state.corrX ? 'selected' : ''}>
                ${escapeHtml(m.label)} (${escapeHtml(m.unit)})
              </option>
            `
              )
              .join('')}
          </select>
        </div>
        <div>
          <label class="form-label">Y-Axis Metric</label>
          <select id="corr-select-y" class="form-select">
            ${(c.availableMetrics || [])
              .map(
                (m) => `
              <option value="${escapeHtml(m.key)}" ${m.key === state.corrY ? 'selected' : ''}>
                ${escapeHtml(m.label)} (${escapeHtml(m.unit)})
              </option>
            `
              )
              .join('')}
          </select>
        </div>
      </div>

      <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:260px;background:rgba(15,23,42,0.55);border-radius:12px;">
        <!-- Regression Line -->
        ${
          pts.length >= 3
            ? `<line
                x1="${mapX(minX).toFixed(1)}"
                y1="${Math.max(padY, Math.min(h - padY, mapY(regY1))).toFixed(1)}"
                x2="${mapX(maxX).toFixed(1)}"
                y2="${Math.max(padY, Math.min(h - padY, mapY(regY2))).toFixed(1)}"
                stroke="#ec4899"
                stroke-width="2.2"
                stroke-dasharray="6 4"
              />`
            : ''
        }
        ${pts
          .map(
            (p) => `
          <circle
            cx="${mapX(p.x).toFixed(1)}"
            cy="${mapY(p.y).toFixed(1)}"
            r="4.5"
            fill="#6366f1"
            stroke="#c7d2fe"
            stroke-width="1"
          >
            <title>${p.day}: X=${p.x}, Y=${p.y}</title>
          </circle>
        `
          )
          .join('')}
      </svg>
      <div style="display:flex;justify-content:space-between;font-size:0.76rem;color:var(--text-muted);margin-top:8px;">
        <span>X: ${escapeHtml(c.metricX?.label)} (${minX} → ${maxX} ${escapeHtml(c.metricX?.unit)})</span>
        <span>Y: ${escapeHtml(c.metricY?.label)} (${minY} → ${maxY} ${escapeHtml(c.metricY?.unit)})</span>
      </div>
    </div>
  `;
}

function renderSettingsView() {
  const user = state.session?.user || {};
  const isAdmin = user.role === 'admin';
  const ov = state.ringOverview || {};
  const hasWebBle = typeof navigator !== 'undefined' && Boolean(navigator.bluetooth);

  return `
    <div class="grid-2">
      <!-- Th0rgal/open_oura Cloud-Free BLE Ring Hub -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">📡 Cloud-Free Oura Ring 3 Hub (open_oura BLE)</div>
            <div class="card-subtitle">
              Engine: <strong style="color:#34d399;">Th0rgal/open_oura (100% Membership-Free)</strong> •
              Key: <strong style="color:${ov.hasRingKey ? '#34d399' : '#fbbf24'}">${ov.hasRingKey ? `Configured (${escapeHtml(ov.maskedKey)})` : 'Ready to Pair / Set Key'}</strong>
            </div>
          </div>
          <span class="tag-chip" style="font-size:0.72rem;">No Oura Cloud</span>
        </div>

        <!-- Ring Telemetry Pills -->
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;">
          <div style="background:rgba(15,23,42,0.55);border:1px solid var(--border-subtle);border-radius:10px;padding:8px 10px;">
            <div style="font-size:0.68rem;color:var(--text-muted);">RING SERIAL</div>
            <div style="font-weight:700;font-size:0.86rem;margin-top:2px;">${escapeHtml(ov.serial || user.ringSerial || `OURA3-${user.id}`)}</div>
          </div>
          <div style="background:rgba(15,23,42,0.55);border:1px solid var(--border-subtle);border-radius:10px;padding:8px 10px;">
            <div style="font-size:0.68rem;color:var(--text-muted);">BATTERY / FW</div>
            <div style="font-weight:700;font-size:0.86rem;margin-top:2px;">
              ${ov.batteryPercent != null ? `${ov.batteryPercent}%` : '--'}
              ${ov.firmware ? `• v${escapeHtml(ov.firmware)}` : ''}
            </div>
          </div>
          <div style="background:rgba(15,23,42,0.55);border:1px solid var(--border-subtle);border-radius:10px;padding:8px 10px;">
            <div style="font-size:0.68rem;color:var(--text-muted);">RING CURSOR</div>
            <div style="font-weight:700;font-size:0.86rem;margin-top:2px;">${ov.cursor || 0} ds</div>
          </div>
          <div style="background:rgba(15,23,42,0.55);border:1px solid var(--border-subtle);border-radius:10px;padding:8px 10px;">
            <div style="font-size:0.68rem;color:var(--text-muted);">RAW BLE EVENTS</div>
            <div style="font-weight:700;font-size:0.86rem;margin-top:2px;color:#a5b4fc;">${ov.totalEvents || 0} pkts</div>
          </div>
        </div>

        <!-- Step 1: 16-Byte Ring Auth Key -->
        <form id="ring-key-form" style="margin-bottom:14px;">
          <label class="form-label">Step 1: 16-Byte Ring Auth Key & Serial (AES-128-ECB Challenge-Response)</label>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:8px;">
            Paste your 32-hex ring auth key from <code>open_oura</code> or click <strong>Generate New Key</strong> to pair a factory-reset ring on its charger dock.
          </div>
          <div style="display:grid;grid-template-columns:140px 1fr;gap:8px;margin-bottom:8px;">
            <input
              class="form-input"
              name="ringSerial"
              value="${escapeHtml(ov.serial || user.ringSerial || `OURA3-${user.id}`)}"
              placeholder="Ring Serial"
            />
            <input
              class="form-input"
              id="ring-key-input"
              name="ringKeyHex"
              value="${escapeHtml(ov.ringKeyHex || '')}"
              placeholder="32-char hex key (e.g. 4431967d8bacc2659743142b68391d9a)"
              style="font-family:monospace;font-size:0.8rem;"
            />
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button type="submit" class="btn btn-primary">Save Ring Key (AES-256)</button>
            <button type="button" id="generate-ring-key-btn" class="btn">🎲 Generate New 16-Byte Key</button>
            ${
              ov.hasRingKey
                ? `<button type="button" id="disconnect-oura-btn" class="btn btn-danger">Clear Key</button>`
                : ''
            }
          </div>
        </form>

        <!-- Step 2: Direct WebBluetooth BLE Sync & Pairing -->
        <div style="padding-top:14px;border-top:1px solid var(--border-subtle);margin-bottom:14px;">
          <label class="form-label">Step 2: Direct Bluetooth (BLE) Ring Sync & Pairing (${escapeHtml(user.displayName)})</label>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:9px;">
            Connects directly to GATT Service <code>98ed0001-a541-11e4-b6a0-0002a5d5c51b</code>: authenticates via <code>0x2c/0x2d</code>, enables Daytime HR/SpO2 (<code>0x26</code>), triggers sleep analysis (<code>0x42</code>), and drains all binary events (<code>0x41..0x8b</code>).
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <button type="button" id="ble-sync-btn" class="btn btn-rose">
              🔵 Connect & Sync Ring via Bluetooth (BLE)
            </button>
            <button type="button" id="ble-pair-reset-btn" class="btn" title="Writes your 16-byte key (0x24) to a factory-reset ring on its dock">
              🔑 Pair Factory-Reset Ring (Write 0x24 Key)
            </button>
            <button type="button" id="ble-simulate-btn" class="btn btn-primary" title="Generates and decodes binary open_oura packets (0x76, 0x5a, 0x5d, 0x75, 0x6f, 0x50)">
              ⚡ Test open_oura Binary BLE Drain (7d)
            </button>
          </div>
          ${
            state.bleStatus
              ? `<div style="margin-top:8px;padding:8px 10px;border-radius:8px;background:rgba(99,102,241,0.14);border:1px solid rgba(99,102,241,0.3);font-size:0.78rem;color:#c7d2fe;">
                  ${escapeHtml(state.bleStatus)}
                </div>`
              : ''
          }
          ${
            !hasWebBle
              ? `<div style="font-size:0.72rem;color:var(--text-muted);margin-top:6px;">
                  Tip: For direct browser BLE on macOS/Desktop use Chrome/Edge/Arc, on iOS use Bluefy or import <code>oura.db</code> from <code>open_oura</code> / <code>open_health</code> below.
                </div>`
              : ''
          }
        </div>

        <!-- Step 3: Charger Dock Factory-Reset Guide -->
        <div style="padding-top:12px;border-top:1px solid var(--border-subtle);">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-size:0.8rem;font-weight:600;color:#cbd5e1;">
              🔄 How to Factory-Reset Your Oura Ring 3 & Use Without Membership
            </span>
            <button type="button" id="toggle-reset-guide-btn" class="btn" style="padding:4px 10px;font-size:0.74rem;">
              ${state.showResetGuide ? 'Hide Guide' : 'Show 4-Flip Dock Guide'}
            </button>
          </div>
          ${
            state.showResetGuide
              ? `
            <div style="margin-top:10px;background:rgba(15,23,42,0.7);border:1px solid var(--border-subtle);border-radius:10px;padding:12px;font-size:0.77rem;color:var(--text-secondary);line-height:1.5;">
              <div><strong>Hardware Factory Reset + Self-Provisioning (from <code>Th0rgal/open_oura</code>):</strong></div>
              <ol style="margin:6px 0 8px 18px;">
                <li><strong>Forget Ring in iOS/macOS Bluetooth settings</strong> and force-quit the official Oura app so it doesn't grab the BLE connection.</li>
                <li>Place your ring on the powered <strong>charging dock</strong> (wait for the LED to light up).</li>
                <li>With the ring on the charger, <strong>flip the charger upside-down, then right-side-up 4 times in a row</strong> (~1 flip per second), then lay the charger flat.</li>
                <li>Wait ~5 seconds — the charger LED will cycle colors, confirming the factory reset (the ring's old auth key is wiped).</li>
                <li>Click <strong>"🎲 Generate New 16-Byte Key"</strong> above, then click <strong>"🔑 Pair Factory-Reset Ring (Write 0x24 Key)"</strong> (or run <code>cargo run -- pair --key &lt;HEX&gt;</code> in <code>./open_oura</code>).</li>
              </ol>
              <div style="color:#34d399;">Once paired, your ring is 100% yours forever — no Oura account, cloud, or subscription needed!</div>
            </div>
          `
              : ''
          }
        </div>
      </div>

      <!-- Profile, open_oura SQLite (oura.db) Import & Archive Card -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">👤 Profile & open_oura SQLite / CSV Import</div>
            <div class="card-subtitle">Import raw <code>oura.db</code> databases or CSV/JSON archives</div>
          </div>
        </div>

        <form id="profile-form">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
            <div class="form-group">
              <label class="form-label">Display Name</label>
              <input class="form-input" name="displayName" value="${escapeHtml(user.displayName || '')}" required />
            </div>
            <div class="form-group">
              <label class="form-label">Oura Ring Model / Finish</label>
              <input class="form-input" name="ringName" value="${escapeHtml(user.ringName || '')}" />
            </div>
          </div>
          <div class="form-group" style="display:flex;gap:14px;align-items:center;">
            <div>
              <label class="form-label">Accent Color</label>
              <input type="color" name="avatarColor" value="${escapeHtml(user.avatarColor || '#6366f1')}" style="height:36px;width:58px;background:none;border:none;cursor:pointer;" />
            </div>
            <label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;margin-top:16px;">
              <input type="checkbox" name="shareWithHousehold" ${user.shareWithHousehold ? 'checked' : ''} />
              Share my ring in Couple / Household Sync view
            </label>
          </div>
          <button type="submit" class="btn btn-primary">Save Profile Settings</button>
        </form>

        <!-- Import open_oura / open_health SQLite (oura.db) -->
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle);">
          <label class="form-label">🗄️ Import <code>open_oura</code> / <code>open_health</code> SQLite Database (<code>oura.db</code>)</label>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:8px;">
            Upload an <code>oura.db</code> file from <code>open_oura</code> CLI (<code>cargo run -- sync</code>) or the <code>open_health</code> iOS app ("Export raw ring data") — Laura decodes all binary <code>events</code> and scores them with <code>ecore</code>:
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <input type="file" id="open-oura-db-file" accept=".db,.sqlite,.sqlite3" class="form-input" style="flex:1;padding:7px;" />
            <button type="button" id="open-oura-db-btn" class="btn btn-primary">Import oura.db</button>
          </div>
        </div>

        <!-- Import CSV / JSON -->
        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle);">
          <label class="form-label">📥 Import CSV / JSON Archive</label>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <input type="file" id="oura-import-file" accept=".csv,.json" class="form-input" style="flex:1;padding:7px;" />
            <button type="button" id="oura-import-btn" class="btn">Import CSV/JSON</button>
          </div>
        </div>

        <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <span style="font-size:0.78rem;color:var(--text-muted);">Export ${escapeHtml(user.displayName)}'s Data:</span>
          <div style="display:flex;gap:8px;">
            <a href="/api/export?format=csv&userId=${user.id}" class="btn" download>⬇ CSV</a>
            <a href="/api/export?format=json&userId=${user.id}" class="btn" download>⬇ JSON</a>
          </div>
        </div>
      </div>
    </div>

    <!-- open_oura Binary Event Stream Inspector -->
    <div class="card" style="margin-bottom:18px;">
      <div class="card-header">
        <div>
          <div class="card-title">🔬 open_oura Decoded Binary Event Stream (${escapeHtml(user.displayName)})</div>
          <div class="card-subtitle">
            On-ring binary event packets (<code>0x41..0x8b</code>) decoded locally and scored via <code>oura-analysis</code> / <code>ecore</code>
          </div>
        </div>
        <button type="button" class="btn" data-sync-days="14">↻ Re-Score Local Events</button>
      </div>
      ${
        (ov.countsByName || []).length > 0
          ? `
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
          ${ov.countsByName
            .map(
              (c) => `
            <span class="tag-chip" style="font-family:monospace;font-size:0.75rem;">
              ${escapeHtml(c.tagHex)} ${escapeHtml(c.name)}: <strong>${c.count}</strong>
            </span>
          `
            )
            .join('')}
        </div>
      `
          : `<p style="font-size:0.82rem;color:var(--text-muted);">No raw binary ring packets stored yet for ${escapeHtml(user.displayName)}. Click <strong>"⚡ Test open_oura Binary BLE Drain (7d)"</strong> or connect your ring via BLE above to populate raw packets.</p>`
      }
    </div>

    <div class="grid-2">
      <!-- Household Admin & Security Card -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">🛡️ Security Layers & Household Admin</div>
            <div class="card-subtitle">PBKDF2-SHA256 / scrypt password hashing, AES-256-GCM at rest, max 3 users</div>
          </div>
        </div>

        ${
          isAdmin
            ? `
          <form id="admin-settings-form" style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border-subtle);">
            <div class="form-group">
              <label class="form-label">Household Title</label>
              <input class="form-input" name="householdName" value="${escapeHtml(state.session?.householdName || '')}" />
            </div>
            <div class="form-group" style="display:flex;gap:12px;align-items:center;justify-content:space-between;">
              <label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;">
                <input type="checkbox" name="registrationLocked" ${state.session?.registrationLocked ? 'checked' : ''} />
                🔒 Lock Public Registration (Only allow existing household logins)
              </label>
            </div>
            <button type="submit" class="btn btn-primary">Save Household Security Config</button>
          </form>

          <!-- Manage Household Accounts (2-3 Users Max) -->
          <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border-subtle);">
            <label class="form-label">👥 Household Member Credentials (${(state.session?.householdMembers || []).length} / 3 Users Max)</label>
            <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:8px;">
              Update usernames, display names, or set new passwords (hashed with 210,000-iteration PBKDF2-SHA256 + 16B salt):
            </div>
            ${(state.session?.householdMembers || [])
              .map(
                (m) => `
              <form class="admin-member-form" data-member-id="${m.id}" style="display:grid;grid-template-columns:110px 1fr 1fr auto;gap:6px;margin-bottom:8px;align-items:center;">
                <input class="form-input" name="username" value="${escapeHtml(m.username)}" placeholder="Username" required style="padding:7px 9px;font-size:0.8rem;" />
                <input class="form-input" name="displayName" value="${escapeHtml(m.displayName)}" placeholder="Display Name" required style="padding:7px 9px;font-size:0.8rem;" />
                <input class="form-input" type="password" name="newPassword" minlength="8" placeholder="New password (8+ chars)" style="padding:7px 9px;font-size:0.8rem;" />
                <button type="submit" class="btn btn-primary" style="padding:7px 10px;font-size:0.78rem;">Save</button>
              </form>
            `
              )
              .join('')}

            ${
              (state.session?.householdMembers || []).length < 3
                ? `
              <form id="admin-add-user-form" style="margin-top:10px;padding-top:10px;border-top:1px dashed var(--border-subtle);display:grid;grid-template-columns:110px 1fr 1fr auto;gap:6px;align-items:center;">
                <input class="form-input" name="username" placeholder="3rd username" required style="padding:7px 9px;font-size:0.8rem;" />
                <input class="form-input" name="displayName" placeholder="Display Name" required style="padding:7px 9px;font-size:0.8rem;" />
                <input class="form-input" type="password" name="password" minlength="8" placeholder="Password (8+ chars)" required style="padding:7px 9px;font-size:0.8rem;" />
                <button type="submit" class="btn" style="padding:7px 10px;font-size:0.78rem;">+ Add 3rd</button>
              </form>
            `
                : ''
            }
          </div>
        `
            : ''
        }

        <form id="password-form">
          <label class="form-label">Change My Password (${escapeHtml(user.username)})</label>
          <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;">
            <input class="form-input" type="password" name="currentPassword" placeholder="Current password" required />
            <input class="form-input" type="password" name="newPassword" minlength="8" placeholder="New password (8+ chars)" required />
            <button type="submit" class="btn">Update</button>
          </div>
        </form>

        <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;">
          <span style="font-size:0.82rem;color:var(--text-muted);">Signed in as <strong>${escapeHtml(user.username)}</strong></span>
          <button type="button" id="logout-btn" class="btn btn-danger">Sign Out</button>
        </div>
      </div>

      <!-- iOS PWA Installation Guide & Sync Logs -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">📱 Install as iOS App & Sync Logs</div>
            <div class="card-subtitle">Use on your and your wife's iPhones with native full-screen UI</div>
          </div>
        </div>

        <div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.28);border-radius:12px;padding:12px 14px;font-size:0.82rem;margin-bottom:14px;">
          <strong>How to use Laura 100% Cloud-Free on iOS & macOS:</strong>
          <ol style="margin:6px 0 0 18px;color:var(--text-secondary);">
            <li>Add Laura to your iPhone Home Screen via Safari (<strong>Share → Add to Home Screen</strong>).</li>
            <li>Sync your ring directly over Bluetooth using Chrome/Mac, Bluefy on iOS, the included <code>./open_oura</code> CLI, or the companion <code>./open_health</code> iOS app.</li>
          </ol>
        </div>

        <div class="card-subtitle" style="margin-bottom:8px;">Recent Sync History</div>
        <table class="table-clean">
          <thead>
            <tr>
              <th>Time</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${(state.syncLogs || [])
              .slice(0, 5)
              .map(
                (l) => `
              <tr>
                <td style="white-space:nowrap;font-size:0.75rem;color:var(--text-muted);">
                  ${new Date(l.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
                <td>
                  <span style="color:${l.status === 'success' ? '#34d399' : '#f87171'};font-weight:700;">
                    ${escapeHtml(l.status)}
                  </span>
                </td>
                <td style="font-size:0.78rem;">${escapeHtml(l.message)}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function render() {
  const root = document.getElementById('app');
  if (!root) return;

  if (!state.session) {
    root.innerHTML = `<div class="auth-wrapper"><div class="card">Loading Laura...</div></div>`;
    return;
  }

  if (!state.session.authenticated) {
    root.innerHTML = `
      ${state.toast ? `<div class="toast-banner">${escapeHtml(state.toast)}</div>` : ''}
      ${renderAuthView()}
    `;
    bindAuthEvents();
    return;
  }

  const members = state.session.householdMembers || [];
  const currentDay = state.selectedDay || new Date().toISOString().slice(0, 10);

  const navItems = [
    {
      id: 'today',
      label: 'Today',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>`
    },
    {
      id: 'couple',
      label: 'Couple Sync',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`
    },
    {
      id: 'trends',
      label: 'Trends & Tags',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`
    },
    {
      id: 'correlations',
      label: 'Correlations',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="7.5" cy="7.5" r="2.5"/><circle cx="16.5" cy="16.5" r="2.5"/><circle cx="16.5" cy="7.5" r="2.5"/><line x1="4" y1="20" x2="20" y2="4"/></svg>`
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`
    }
  ];

  root.innerHTML = `
    ${state.toast ? `<div class="toast-banner">${escapeHtml(state.toast)}</div>` : ''}
    <div class="app-shell">
      <!-- Desktop Sidebar -->
      <aside class="sidebar-nav">
        <div class="brand-header" style="margin-bottom:8px;">
          <img src="./icon.svg" alt="Laura" style="width:38px;height:38px;border-radius:10px;" />
          <div>
            <div style="font-weight:800;font-size:1.15rem;">Laura</div>
            <div style="font-size:0.73rem;color:var(--text-muted);">${escapeHtml(state.session.householdName)}</div>
          </div>
        </div>

        <div class="sidebar-links">
          ${navItems
            .map(
              (item) => `
            <button class="sidebar-btn ${state.activeTab === item.id ? 'active' : ''}" data-nav="${item.id}">
              ${item.icon}
              <span>${item.label}</span>
            </button>
          `
            )
            .join('')}
        </div>

        <div style="padding-top:12px;border-top:1px solid var(--border-subtle);font-size:0.76rem;color:var(--text-muted);">
          <div>Logged in: <strong style="color:var(--text-primary)">${escapeHtml(state.session.user.displayName)}</strong></div>
          <div style="margin-top:3px;">${escapeHtml(state.session.user.ringName)}</div>
        </div>
      </aside>

      <!-- Main Content -->
      <main class="main-area">
        <!-- Topbar with Ring Switcher & Date Controls -->
        <header class="topbar">
          <div class="member-pills">
            ${members
              .map(
                (m) => `
              <button
                class="member-pill ${Number(state.selectedUserId) === Number(m.id) ? 'active' : ''}"
                data-select-user="${m.id}"
              >
                <span class="avatar-dot" style="background:${escapeHtml(m.avatarColor)}"></span>
                <span>${escapeHtml(m.displayName)}</span>
              </button>
            `
              )
              .join('')}
          </div>

          <div class="date-controls">
            <button class="icon-btn" id="prev-day-btn" title="Previous Day">←</button>
            <input type="date" id="date-picker" class="date-input" value="${escapeHtml(currentDay)}" />
            <button class="icon-btn" id="next-day-btn" title="Next Day">→</button>
            <button class="icon-btn" id="latest-day-btn">Latest</button>
            <button class="btn btn-primary" id="quick-sync-btn">↻ Sync Ring</button>
          </div>
        </header>

        ${state.activeTab === 'today' ? renderTodayView() : ''}
        ${state.activeTab === 'couple' ? renderCoupleView() : ''}
        ${state.activeTab === 'trends' ? renderTrendsView() : ''}
        ${state.activeTab === 'correlations' ? renderCorrelationsView() : ''}
        ${state.activeTab === 'settings' ? renderSettingsView() : ''}
      </main>

      <!-- iOS Bottom Navigation Bar -->
      <nav class="bottom-nav">
        ${navItems
          .map(
            (item) => `
          <button class="nav-item ${state.activeTab === item.id ? 'active' : ''}" data-nav="${item.id}">
            ${item.icon}
            <span>${item.label}</span>
          </button>
        `
          )
          .join('')}
      </nav>
    </div>
  `;

  bindDashboardEvents();
}

function bindAuthEvents() {
  document.querySelectorAll('[data-select-login-user]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const username = btn.getAttribute('data-select-login-user');
      const uInput = document.getElementById('login-username-input');
      const pInput = document.getElementById('login-password-input');
      if (uInput) uInput.value = username;
      if (pInput) pInput.focus();
    });
  });

  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(loginForm);
      try {
        await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({
            username: fd.get('username'),
            password: fd.get('password')
          })
        });
        state.selectedUserId = null;
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(registerForm);
      try {
        await api('/api/auth/register', {
          method: 'POST',
          body: JSON.stringify({
            username: fd.get('username'),
            displayName: fd.get('displayName'),
            ringName: fd.get('ringName'),
            password: fd.get('password')
          })
        });
        state.selectedUserId = null;
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const toggleReg = document.getElementById('toggle-register');
  if (toggleReg) {
    toggleReg.addEventListener('click', (e) => {
      e.preventDefault();
      state.authModeView = 'register';
      render();
    });
  }

  const toggleLogin = document.getElementById('toggle-login');
  if (toggleLogin) {
    toggleLogin.addEventListener('click', (e) => {
      e.preventDefault();
      state.authModeView = 'login';
      render();
    });
  }
}

function bindDashboardEvents() {
  document.querySelectorAll('[data-nav]').forEach((btn) => {
    btn.addEventListener('click', () => setTab(btn.getAttribute('data-nav')));
  });

  document.querySelectorAll('[data-select-user]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedUserId = Number(btn.getAttribute('data-select-user'));
      loadCurrentTabData();
    });
  });

  const prevBtn = document.getElementById('prev-day-btn');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      const cur = state.selectedDay || new Date().toISOString().slice(0, 10);
      state.selectedDay = shiftDay(cur, -1);
      loadCurrentTabData();
    });
  }

  const nextBtn = document.getElementById('next-day-btn');
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      const cur = state.selectedDay || new Date().toISOString().slice(0, 10);
      state.selectedDay = shiftDay(cur, 1);
      loadCurrentTabData();
    });
  }

  const latestBtn = document.getElementById('latest-day-btn');
  if (latestBtn) {
    latestBtn.addEventListener('click', () => {
      state.selectedDay = state.dailyData?.latestDay || new Date().toISOString().slice(0, 10);
      loadCurrentTabData();
    });
  }

  const datePicker = document.getElementById('date-picker');
  if (datePicker) {
    datePicker.addEventListener('change', (e) => {
      if (e.target.value) {
        state.selectedDay = e.target.value;
        loadCurrentTabData();
      }
    });
  }

  const quickSync = document.getElementById('quick-sync-btn');
  if (quickSync) {
    quickSync.addEventListener('click', async () => {
      try {
        showToast('Syncing Oura Ring data...');
        const res = await api('/api/oura/sync', {
          method: 'POST',
          body: JSON.stringify({ daysBack: 14 })
        });
        showToast(res.message || `Synced ${res.daysSynced} days!`);
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  // Toggle tags on Today view
  document.querySelectorAll('[data-toggle-tag]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const tag = btn.getAttribute('data-toggle-tag');
      const curTags = [...(state.dailyData?.summary?.tags || [])];
      const idx = curTags.indexOf(tag);
      if (idx > -1) curTags.splice(idx, 1);
      else curTags.push(tag);

      try {
        await api('/api/dashboard/note', {
          method: 'POST',
          body: JSON.stringify({
            day: state.selectedDay,
            customNote: state.dailyData?.summary?.customNote || '',
            tags: curTags
          })
        });
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  });

  const noteForm = document.getElementById('daily-note-form');
  if (noteForm) {
    noteForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(noteForm);
      try {
        await api('/api/dashboard/note', {
          method: 'POST',
          body: JSON.stringify({
            day: state.selectedDay,
            customNote: fd.get('customNote'),
            tags: state.dailyData?.summary?.tags || []
          })
        });
        showToast('Saved daily note!');
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  // Couple metric buttons
  document.querySelectorAll('[data-couple-metric]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.coupleMetric = btn.getAttribute('data-couple-metric');
      render();
    });
  });

  // Trends controls
  document.querySelectorAll('[data-trends-days]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.trendsDays = Number(btn.getAttribute('data-trends-days'));
      loadCurrentTabData();
    });
  });

  document.querySelectorAll('[data-trends-metric]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.trendsMetric = btn.getAttribute('data-trends-metric');
      render();
    });
  });

  // Correlations controls
  document.querySelectorAll('[data-corr-days]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.corrDays = Number(btn.getAttribute('data-corr-days'));
      loadCurrentTabData();
    });
  });

  document.querySelectorAll('[data-corr-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const [x, y] = btn.getAttribute('data-corr-preset').split(':');
      state.corrX = x;
      state.corrY = y;
      loadCurrentTabData();
    });
  });

  const selX = document.getElementById('corr-select-x');
  if (selX) {
    selX.addEventListener('change', (e) => {
      state.corrX = e.target.value;
      loadCurrentTabData();
    });
  }

  const selY = document.getElementById('corr-select-y');
  if (selY) {
    selY.addEventListener('change', (e) => {
      state.corrY = e.target.value;
      loadCurrentTabData();
    });
  }

  // Settings events (`Th0rgal/open_oura` Cloud-Free BLE & SQLite Hub)
  const ringKeyForm = document.getElementById('ring-key-form');
  if (ringKeyForm) {
    ringKeyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(ringKeyForm);
      try {
        await api('/api/ring/key', {
          method: 'POST',
          body: JSON.stringify({
            ringSerial: fd.get('ringSerial'),
            ringKeyHex: fd.get('ringKeyHex')
          })
        });
        showToast('Saved 16-byte Ring Auth Key (AES-256-GCM encrypted at rest)!');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const genKeyBtn = document.getElementById('generate-ring-key-btn');
  if (genKeyBtn) {
    genKeyBtn.addEventListener('click', async () => {
      try {
        const res = await api('/api/ring/key', {
          method: 'POST',
          body: JSON.stringify({ generate: true })
        });
        const input = document.getElementById('ring-key-input');
        if (input && res.ringKeyHex) input.value = res.ringKeyHex;
        showToast('Generated new 16-byte Ring Auth Key! Ready to pair a factory-reset ring.');
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const toggleResetBtn = document.getElementById('toggle-reset-guide-btn');
  if (toggleResetBtn) {
    toggleResetBtn.addEventListener('click', () => {
      state.showResetGuide = !state.showResetGuide;
      render();
    });
  }

  const bleSyncBtn = document.getElementById('ble-sync-btn');
  if (bleSyncBtn) {
    bleSyncBtn.addEventListener('click', () => {
      runWebBluetoothRingSync({ pairNewKey: false });
    });
  }

  const blePairBtn = document.getElementById('ble-pair-reset-btn');
  if (blePairBtn) {
    blePairBtn.addEventListener('click', () => {
      runWebBluetoothRingSync({ pairNewKey: true });
    });
  }

  const bleSimBtn = document.getElementById('ble-simulate-btn');
  if (bleSimBtn) {
    bleSimBtn.addEventListener('click', async () => {
      try {
        state.bleStatus = 'Generating & decoding open_oura BLE binary frames (0x76, 0x5a, 0x5d, 0x75, 0x6f, 0x50)...';
        render();
        const res = await api('/api/ring/sync', {
          method: 'POST',
          body: JSON.stringify({ daysBack: 7, simulateBle: true })
        });
        state.bleStatus = `open_oura BLE sync complete: decoded ${res.eventsIngested} raw binary packets → scored ${res.daysSynced} days via ecore.`;
        showToast(res.message);
        await loadCurrentTabData();
      } catch (err) {
        state.bleStatus = `Error: ${err.message}`;
        showToast(err.message);
      }
    });
  }

  const importDbBtn = document.getElementById('open-oura-db-btn');
  if (importDbBtn) {
    importDbBtn.addEventListener('click', async () => {
      const fileInput = document.getElementById('open-oura-db-file');
      const file = fileInput?.files?.[0];
      if (!file) {
        showToast('Please select an open_oura / open_health SQLite (.db) file first.');
        return;
      }
      try {
        showToast(`Importing ${file.name} via open_oura binary decoder...`);
        const buf = await file.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const base64Db = btoa(binary);
        const res = await api('/api/ring/import-db', {
          method: 'POST',
          body: JSON.stringify({ filename: file.name, base64Db })
        });
        showToast(`Imported ${res.eventsImported} binary ring events (${res.daysUpdated} days scored)!`);
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const importBtn = document.getElementById('oura-import-btn');
  if (importBtn) {
    importBtn.addEventListener('click', async () => {
      const fileInput = document.getElementById('oura-import-file');
      const file = fileInput?.files?.[0];
      if (!file) {
        showToast('Please select a .csv or .json export file first.');
        return;
      }
      try {
        const content = await file.text();
        const res = await api('/api/oura/import', {
          method: 'POST',
          body: JSON.stringify({ filename: file.name, content })
        });
        showToast(`Imported ${res.daysImported} days from ${file.name}!`);
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const disconnectBtn = document.getElementById('disconnect-oura-btn');
  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', async () => {
      try {
        await api('/api/ring/key', { method: 'DELETE' });
        showToast('Cleared Ring Auth Key.');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  document.querySelectorAll('[data-sync-days]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const daysBack = Number(btn.getAttribute('data-sync-days'));
      try {
        showToast(`Re-scoring local open_oura ring events...`);
        const res = await api('/api/ring/sync', {
          method: 'POST',
          body: JSON.stringify({ daysBack })
        });
        showToast(res.message || `Synced ${res.daysSynced} days!`);
        await loadCurrentTabData();
      } catch (err) {
        showToast(err.message);
      }
    });
  });

  const profileForm = document.getElementById('profile-form');
  if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(profileForm);
      try {
        await api('/api/user/profile', {
          method: 'PUT',
          body: JSON.stringify({
            displayName: fd.get('displayName'),
            ringName: fd.get('ringName'),
            avatarColor: fd.get('avatarColor'),
            shareWithHousehold: fd.get('shareWithHousehold') === 'on'
          })
        });
        showToast('Profile settings saved!');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const adminForm = document.getElementById('admin-settings-form');
  if (adminForm) {
    adminForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(adminForm);
      try {
        await api('/api/admin/settings', {
          method: 'PUT',
          body: JSON.stringify({
            householdName: fd.get('householdName'),
            registrationLocked: fd.get('registrationLocked') === 'on'
          })
        });
        showToast('Security & household settings updated!');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  document.querySelectorAll('.admin-member-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const memberId = Number(form.getAttribute('data-member-id'));
      const fd = new FormData(form);
      try {
        await api('/api/admin/users', {
          method: 'POST',
          body: JSON.stringify({
            action: 'update',
            userId: memberId,
            username: fd.get('username'),
            displayName: fd.get('displayName'),
            newPassword: fd.get('newPassword') || undefined
          })
        });
        showToast('Updated household member credentials (hashed with PBKDF2-SHA256)!');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  });

  const adminAddUserForm = document.getElementById('admin-add-user-form');
  if (adminAddUserForm) {
    adminAddUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(adminAddUserForm);
      try {
        await api('/api/auth/register', {
          method: 'POST',
          body: JSON.stringify({
            username: fd.get('username'),
            displayName: fd.get('displayName'),
            password: fd.get('password'),
            ringName: 'Oura Ring Gen 3'
          })
        });
        showToast('Added 3rd household member!');
        await refreshSession();
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const passwordForm = document.getElementById('password-form');
  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(passwordForm);
      try {
        await api('/api/user/password', {
          method: 'PUT',
          body: JSON.stringify({
            currentPassword: fd.get('currentPassword'),
            newPassword: fd.get('newPassword')
          })
        });
        passwordForm.reset();
        showToast('Password updated!');
      } catch (err) {
        showToast(err.message);
      }
    });
  }

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await api('/api/auth/logout', { method: 'POST' });
      state.selectedUserId = null;
      await refreshSession();
    });
  }
}

function hexToUint8(hex) {
  const clean = hex.replace(/\s+/g, '').replace(/^0x/i, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uint8ToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function runWebBluetoothRingSync({ pairNewKey = false } = {}) {
  if (!navigator.bluetooth) {
    showToast('WebBluetooth is not enabled in this browser. Use Chrome/Edge/Arc on Desktop, Bluefy on iOS, or click "Test open_oura Binary BLE Drain".');
    return;
  }

  const proto = state.ringOverview?.bleProtocol || {
    serviceUuid: '98ed0001-a541-11e4-b6a0-0002a5d5c51b',
    writeUuid: '98ed0002-a541-11e4-b6a0-0002a5d5c51b',
    notifyUuid: '98ed0003-a541-11e4-b6a0-0002a5d5c51b'
  };

  try {
    state.bleStatus = 'Scanning for Oura Ring 3 over Bluetooth LE (98ed0001-a541-11e4-b6a0-0002a5d5c51b)...';
    render();

    const device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [proto.serviceUuid] }, { namePrefix: 'Oura' }],
      optionalServices: [proto.serviceUuid]
    });

    state.bleStatus = `Connecting to ${device.name || 'Oura Ring'} GATT server...`;
    render();

    const server = await device.gatt.connect();
    const service = await server.getPrimaryService(proto.serviceUuid);
    const writeChar = await service.getCharacteristic(proto.writeUuid);
    const notifyChar = await service.getCharacteristic(proto.notifyUuid);

    const collectedNotificationsHex = [];
    let latestNonceHex = null;
    let authStatusByte = null;

    await notifyChar.startNotifications();
    notifyChar.addEventListener('characteristicvaluechanged', (event) => {
      const val = new Uint8Array(event.target.value.buffer);
      const hex = uint8ToHex(val);
      collectedNotificationsHex.push(hex);

      // Check for 0x2f 0x10 0x2c <15B nonce>
      if (val[0] === 0x2f && val[2] === 0x2c && val.length >= 18) {
        latestNonceHex = uint8ToHex(val.slice(3, 18));
      }
      // Check for 0x2f 0x02 0x2e <status>
      if (val[0] === 0x2f && val[2] === 0x2e && val.length >= 4) {
        authStatusByte = val[3];
      }
    });

    const writeHex = async (hexStr, waitMs = 250) => {
      await writeChar.writeValue(hexToUint8(hexStr));
      await new Promise((r) => setTimeout(r, waitMs));
    };

    const cmds = proto.commandsHex || {};

    if (pairNewKey) {
      state.bleStatus = 'Writing 16-byte Ring Auth Key (0x24) to factory-reset ring...';
      render();
      const keyRes = await api('/api/ring/key', { method: 'POST', body: JSON.stringify({}) });
      if (!keyRes.setKeyPacketHex) {
        throw new Error('Generate or save a 16-byte Ring Auth Key in Step 1 first.');
      }
      await writeHex(keyRes.setKeyPacketHex, 400);
    }

    // 1. Read Firmware, Battery, Serial
    state.bleStatus = 'Reading Ring Firmware (0x0a), Battery (0x0c), and Serial (0x10)...';
    render();
    if (cmds.reqFirmware) await writeHex(cmds.reqFirmware, 200);
    if (cmds.reqBattery) await writeHex(cmds.reqBattery, 200);
    if (cmds.reqSerial) await writeHex(cmds.reqSerial, 200);

    // 2. Authenticate via AES-128-ECB Nonce Challenge (0x2f 0x01 0x2b -> 0x2f 0x11 0x2d)
    state.bleStatus = 'Requesting 15-byte Auth Nonce (0x2f 0x01 0x2b)...';
    render();
    await writeHex(cmds.reqAuthNonce || '2f012b', 450);

    if (latestNonceHex) {
      state.bleStatus = 'Encrypting Nonce with AES-128-ECB/PKCS7 (0x2f 0x11 0x2d)...';
      render();
      const solved = await api('/api/ring/ble-auth', {
        method: 'POST',
        body: JSON.stringify({ nonceHex: latestNonceHex })
      });
      await writeHex(solved.authPacketHex, 450);
    }

    // 3. Sync Ring Clock, Enable Daytime HR / SpO2 / Resting HR, Trigger Sleep Analysis
    state.bleStatus = 'Syncing ring clock (0x12), enabling HR/SpO2 sensors (0x26), and triggering sleep analysis (0x42)...';
    render();
    if (cmds.reqSyncTime) await writeHex(cmds.reqSyncTime, 200);
    if (cmds.enableDaytimeHr) await writeHex(cmds.enableDaytimeHr, 150);
    if (cmds.enableExerciseHr) await writeHex(cmds.enableExerciseHr, 150);
    if (cmds.enableSpo2) await writeHex(cmds.enableSpo2, 150);
    if (cmds.enableRestingHr) await writeHex(cmds.enableRestingHr, 150);
    if (cmds.reqCheckSleepAnalysis) await writeHex(cmds.reqCheckSleepAnalysis, 500);

    // 4. Drain History Events from cursor
    state.bleStatus = 'Draining binary history events (0x10 0x09)...';
    render();
    if (cmds.reqGetEventFromCursor) {
      await writeHex(cmds.reqGetEventFromCursor, 1800);
    }

    device.gatt.disconnect();

    // 5. Ingest collected binary packets on the server
    state.bleStatus = `Uploading ${collectedNotificationsHex.length} BLE frames to local open_oura decoder...`;
    render();
    const res = await api('/api/ring/ingest', {
      method: 'POST',
      body: JSON.stringify({
        serial: device.name || state.ringOverview?.serial || 'OURA3',
        notificationsHex: collectedNotificationsHex,
        phoneUnix: Math.floor(Date.now() / 1000)
      })
    });

    state.bleStatus = `Synced ${res.eventsIngested} events (${res.daysUpdated} days updated)!`;
    showToast(`BLE Ring Sync complete: ${res.eventsIngested} packets decoded!`);
    await loadCurrentTabData();
  } catch (err) {
    state.bleStatus = `BLE Sync note: ${err.message}`;
    showToast(err.message);
    render();
  }
}

initApp();
