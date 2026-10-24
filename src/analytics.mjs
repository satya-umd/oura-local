import {
  listHouseholdUsers,
  getUserById,
  getDailySummary,
  getDailySummariesRange,
  getUserBaselines,
  getCycleLogsForUser,
  getCycleLog,
  toLocalDayStr
} from './db.mjs';

function subtractDays(dayStr, numDays) {
  const [y, m, d] = String(dayStr).split('-').map(Number);
  const dt = new Date(y, (m || 1) - 1, (d || 1) - numDays, 12, 0, 0);
  return toLocalDayStr(dt);
}

function addDays(dayStr, numDays) {
  return subtractDays(dayStr, -numDays);
}

function daysBetween(dayA, dayB) {
  const [y1, m1, d1] = String(dayA).split('-').map(Number);
  const [y2, m2, d2] = String(dayB).split('-').map(Number);
  const t1 = new Date(y1, (m1 || 1) - 1, d1 || 1, 12, 0, 0).getTime();
  const t2 = new Date(y2, (m2 || 1) - 1, d2 || 1, 12, 0, 0).getTime();
  return Math.round((t2 - t1) / 86400000);
}

function parseBedtimeHour(isoStr) {
  if (!isoStr) return null;
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return null;
  let hr = d.getHours() + d.getMinutes() / 60;
  // Normalize evening hours (e.g. 21:00 -> 21.0, 01:00 AM -> 25.0) so bedtime order is continuous
  if (hr < 14) hr += 24;
  return Number(hr.toFixed(2));
}

export function buildCoupleComparison(targetDay) {
  const allUsers = listHouseholdUsers().filter((u) => u.shareWithHousehold);
  const start14 = subtractDays(targetDay, 13);
  const start30 = subtractDays(targetDay, 29);

  const memberCards = allUsers.map((user) => {
    const summary = getDailySummary(user.id, targetDay);
    const baseline = getUserBaselines(user.id, targetDay, 30);
    const series14 = getDailySummariesRange(user.id, start14, targetDay);
    const series30 = getDailySummariesRange(user.id, start30, targetDay);

    const rhrDelta =
      summary?.sleep?.lowestHr != null && baseline.lowestHr != null
        ? Number((summary.sleep.lowestHr - baseline.lowestHr).toFixed(1))
        : null;
    const hrvDelta =
      summary?.sleep?.averageHrv != null && baseline.averageHrv != null
        ? Math.round(summary.sleep.averageHrv - baseline.averageHrv)
        : null;

    let recoveryStatus = 'Optimal Recovery';
    let recoveryLevel = 'high';
    const rScore = summary?.readiness?.score ?? 0;
    if (rScore >= 82) {
      recoveryStatus = 'Peak Readiness — Primed for high activity';
      recoveryLevel = 'high';
    } else if (rScore >= 72) {
      recoveryStatus = 'Steady Recovery — Balanced day ahead';
      recoveryLevel = 'good';
    } else if (rScore > 0) {
      recoveryStatus = 'Needs Extra Rest — Prioritize gentle recovery';
      recoveryLevel = 'low';
    } else {
      recoveryStatus = 'No ring data for this date';
      recoveryLevel = 'none';
    }

    return {
      user,
      summary,
      baseline,
      cycleStatus: buildMemberCycleBrief(user.id, targetDay),
      deltas: {
        rhrDelta,
        hrvDelta,
        readinessDelta: summary?.readiness?.score != null ? summary.readiness.score - baseline.readiness : null,
        sleepDelta: summary?.sleep?.score != null ? summary.sleep.score - baseline.sleep : null
      },
      recoveryStatus,
      recoveryLevel,
      series14,
      series30
    };
  });

  // Compute sleep overlap and shared streaks if at least 2 members
  let sleepOverlap = null;
  let sharedStreaks = { readiness75: 0, sleep75: 0, steps8k: 0 };
  let briefing = {
    headline: 'Add a second household member to unlock Couple Recovery Sync',
    detail: 'Invite your partner or enable household sharing in Settings.',
    tone: 'neutral'
  };

  if (memberCards.length >= 2) {
    const [m1, m2] = memberCards;
    const s1 = m1.summary;
    const s2 = m2.summary;

    if (s1?.sleep?.bedtimeStart && s1?.sleep?.bedtimeEnd && s2?.sleep?.bedtimeStart && s2?.sleep?.bedtimeEnd) {
      const start1 = new Date(s1.sleep.bedtimeStart).getTime();
      const end1 = new Date(s1.sleep.bedtimeEnd).getTime();
      const start2 = new Date(s2.sleep.bedtimeStart).getTime();
      const end2 = new Date(s2.sleep.bedtimeEnd).getTime();

      const unionStart = Math.min(start1, start2);
      const unionEnd = Math.max(end1, end2);
      const overlapStart = Math.max(start1, start2);
      const overlapEnd = Math.min(end1, end2);
      const overlapMs = Math.max(0, overlapEnd - overlapStart);
      const unionMs = Math.max(1, unionEnd - unionStart);

      sleepOverlap = {
        overlapHours: Number((overlapMs / 3600000).toFixed(1)),
        overlapPercent: Math.round((overlapMs / unionMs) * 100),
        bedtimeDiffMinutes: Math.round(Math.abs(start1 - start2) / 60000),
        wakeDiffMinutes: Math.round(Math.abs(end1 - end2) / 60000),
        unionStartIso: new Date(unionStart).toISOString(),
        unionEndIso: new Date(unionEnd).toISOString(),
        member1: {
          name: m1.user.displayName,
          bedtimeStart: s1.sleep.bedtimeStart,
          bedtimeEnd: s1.sleep.bedtimeEnd,
          offsetStartPct: Math.round(((start1 - unionStart) / unionMs) * 100),
          widthPct: Math.round(((end1 - start1) / unionMs) * 100)
        },
        member2: {
          name: m2.user.displayName,
          bedtimeStart: s2.sleep.bedtimeStart,
          bedtimeEnd: s2.sleep.bedtimeEnd,
          offsetStartPct: Math.round(((start2 - unionStart) / unionMs) * 100),
          widthPct: Math.round(((end2 - start2) / unionMs) * 100)
        }
      };
    }

    // Calculate shared streaks backwards from targetDay
    const map2 = new Map(m2.series30.map((d) => [d.day, d]));
    const reversed1 = [...m1.series30].reverse();

    for (const d1 of reversed1) {
      const d2 = map2.get(d1.day);
      if ((d1?.readiness?.score ?? 0) >= 75 && (d2?.readiness?.score ?? 0) >= 75) {
        sharedStreaks.readiness75 += 1;
      } else {
        break;
      }
    }
    for (const d1 of reversed1) {
      const d2 = map2.get(d1.day);
      if ((d1?.sleep?.score ?? 0) >= 75 && (d2?.sleep?.score ?? 0) >= 75) {
        sharedStreaks.sleep75 += 1;
      } else {
        break;
      }
    }
    for (const d1 of reversed1) {
      const d2 = map2.get(d1.day);
      if ((d1?.activity?.steps ?? 0) >= 7500 && (d2?.activity?.steps ?? 0) >= 7500) {
        sharedStreaks.steps8k += 1;
      } else {
        break;
      }
    }

    // Generate smart couple briefing
    const r1 = s1?.readiness?.score ?? 0;
    const r2 = s2?.readiness?.score ?? 0;
    if (r1 >= 80 && r2 >= 80) {
      briefing = {
        headline: `Both ${m1.user.displayName} (${r1}) & ${m2.user.displayName} (${r2}) are in Peak Recovery!`,
        detail: `Great day to tackle a workout together or plan an active evening. Your shared sleep window overlapped by ${sleepOverlap?.overlapPercent ?? 85}%.`,
        tone: 'high'
      };
    } else if (r1 < 72 && r2 >= 80) {
      briefing = {
        headline: `${m1.user.displayName} needs extra rest today (${r1}), while ${m2.user.displayName} is well-recovered (${r2}).`,
        detail: `${m1.user.displayName}'s HRV (${s1?.sleep?.averageHrv ?? '--'} ms) and RHR (${s1?.sleep?.lowestHr ?? '--'} bpm) suggest taking a lighter load today.`,
        tone: 'mixed'
      };
    } else if (r2 < 72 && r1 >= 80) {
      briefing = {
        headline: `${m2.user.displayName} needs extra recovery today (${r2}), while ${m1.user.displayName} is at ${r1}.`,
        detail: `${m2.user.displayName}'s body signals suggest a restorative day and an early wind-down tonight.`,
        tone: 'mixed'
      };
    } else if (r1 < 72 && r2 < 72 && r1 > 0 && r2 > 0) {
      briefing = {
        headline: `Restorative Day for Both (${r1} & ${r2})`,
        detail: `Both rings show elevated recovery demand today. Prioritize hydration, lower daytime stress, and an earlier bedtime tonight.`,
        tone: 'low'
      };
    } else {
      briefing = {
        headline: `Balanced Household Readiness — ${m1.user.displayName} (${r1}) & ${m2.user.displayName} (${r2})`,
        detail: `Steady baselines across both rings. Keep your evening wind-down consistent to build on your ${sharedStreaks.sleep75}-day sleep streak.`,
        tone: 'good'
      };
    }
  }

  return {
    day: targetDay,
    members: memberCards,
    sleepOverlap,
    sharedStreaks,
    briefing
  };
}

const METRIC_EXTRACTORS = {
  bedtime_hour: {
    label: 'Bedtime Hour (24h+, e.g. 22.5 = 10:30 PM)',
    unit: 'hr',
    extract: (d) => parseBedtimeHour(d.sleep?.bedtimeStart)
  },
  total_sleep_hours: {
    label: 'Total Sleep Duration',
    unit: 'hrs',
    extract: (d) => (d.sleep?.totalSeconds ? Number((d.sleep.totalSeconds / 3600).toFixed(2)) : null)
  },
  deep_sleep_minutes: {
    label: 'Deep Sleep',
    unit: 'min',
    extract: (d) => (d.sleep?.deepSeconds != null ? Math.round(d.sleep.deepSeconds / 60) : null)
  },
  rem_sleep_minutes: {
    label: 'REM Sleep',
    unit: 'min',
    extract: (d) => (d.sleep?.remSeconds != null ? Math.round(d.sleep.remSeconds / 60) : null)
  },
  sleep_score: {
    label: 'Sleep Score',
    unit: 'pts',
    extract: (d) => d.sleep?.score ?? null
  },
  readiness_score: {
    label: 'Readiness Score',
    unit: 'pts',
    extract: (d) => d.readiness?.score ?? null
  },
  activity_score: {
    label: 'Activity Score',
    unit: 'pts',
    extract: (d) => d.activity?.score ?? null
  },
  average_hrv: {
    label: 'Nighttime HRV',
    unit: 'ms',
    extract: (d) => d.sleep?.averageHrv ?? null
  },
  lowest_hr: {
    label: 'Lowest Resting HR',
    unit: 'bpm',
    extract: (d) => d.sleep?.lowestHr ?? null
  },
  steps: {
    label: 'Daily Steps',
    unit: 'steps',
    extract: (d) => d.activity?.steps ?? null
  },
  active_calories: {
    label: 'Active Calories',
    unit: 'kcal',
    extract: (d) => d.activity?.activeCalories ?? null
  },
  stress_minutes: {
    label: 'Daytime High Stress',
    unit: 'min',
    extract: (d) => (d.stress?.stressHighSeconds != null ? Math.round(d.stress.stressHighSeconds / 60) : null)
  },
  temp_deviation: {
    label: 'Body Temp Deviation',
    unit: '°C',
    extract: (d) => d.readiness?.tempDeviation ?? null
  },
  spo2_percentage: {
    label: 'Blood Oxygen (SpO2)',
    unit: '%',
    extract: (d) => d.spo2?.percentage ?? null
  }
};

export function computeCorrelation(userId, endDay, days = 60, metricX = 'bedtime_hour', metricY = 'deep_sleep_minutes') {
  const startDay = subtractDays(endDay, days - 1);
  const summaries = getDailySummariesRange(userId, startDay, endDay);
  const extX = METRIC_EXTRACTORS[metricX] || METRIC_EXTRACTORS.bedtime_hour;
  const extY = METRIC_EXTRACTORS[metricY] || METRIC_EXTRACTORS.deep_sleep_minutes;

  const points = [];
  for (const s of summaries) {
    const x = extX.extract(s);
    const y = extY.extract(s);
    if (x != null && y != null && Number.isFinite(x) && Number.isFinite(y)) {
      points.push({
        day: s.day,
        x,
        y,
        tags: s.tags || []
      });
    }
  }

  let r = 0;
  let slope = 0;
  let intercept = 0;
  if (points.length >= 3) {
    const n = points.length;
    const meanX = points.reduce((acc, p) => acc + p.x, 0) / n;
    const meanY = points.reduce((acc, p) => acc + p.y, 0) / n;
    let num = 0;
    let denX = 0;
    let denY = 0;
    for (const p of points) {
      const dx = p.x - meanX;
      const dy = p.y - meanY;
      num += dx * dy;
      denX += dx * dx;
      denY += dy * dy;
    }
    if (denX > 0 && denY > 0) {
      r = Number((num / Math.sqrt(denX * denY)).toFixed(3));
      slope = Number((num / denX).toFixed(4));
      intercept = Number((meanY - slope * meanX).toFixed(4));
    }
  }

  const absR = Math.abs(r);
  let strength = 'No clear linear correlation';
  if (absR >= 0.6) strength = r > 0 ? 'Strong positive correlation' : 'Strong inverse correlation';
  else if (absR >= 0.35) strength = r > 0 ? 'Moderate positive correlation' : 'Moderate inverse correlation';
  else if (absR >= 0.18) strength = r > 0 ? 'Mild positive trend' : 'Mild inverse trend';

  return {
    metricX: { key: metricX, ...extX },
    metricY: { key: metricY, ...extY },
    availableMetrics: Object.entries(METRIC_EXTRACTORS).map(([key, val]) => ({
      key,
      label: val.label,
      unit: val.unit
    })),
    days,
    points,
    pearsonR: r,
    slope,
    intercept,
    strength
  };
}

export function computeTagImpacts(userId, endDay, days = 90) {
  const startDay = subtractDays(endDay, days - 1);
  const summaries = getDailySummariesRange(userId, startDay, endDay);
  if (summaries.length === 0) return [];

  const avgHrv = summaries.reduce((a, s) => a + (s.sleep?.averageHrv || 0), 0) / summaries.length;
  const avgRhr = summaries.reduce((a, s) => a + (s.sleep?.lowestHr || 0), 0) / summaries.length;
  const avgSleep = summaries.reduce((a, s) => a + (s.sleep?.score || 0), 0) / summaries.length;
  const avgDeepMin = summaries.reduce((a, s) => a + ((s.sleep?.deepSeconds || 0) / 60), 0) / summaries.length;

  const tagBuckets = new Map();
  for (const s of summaries) {
    for (const tag of s.tags || []) {
      if (!tagBuckets.has(tag)) tagBuckets.set(tag, []);
      tagBuckets.get(tag).push(s);
    }
  }

  const results = [];
  for (const [tag, items] of tagBuckets.entries()) {
    if (items.length < 2) continue;
    const tagHrv = items.reduce((a, s) => a + (s.sleep?.averageHrv || 0), 0) / items.length;
    const tagRhr = items.reduce((a, s) => a + (s.sleep?.lowestHr || 0), 0) / items.length;
    const tagSleep = items.reduce((a, s) => a + (s.sleep?.score || 0), 0) / items.length;
    const tagDeepMin = items.reduce((a, s) => a + ((s.sleep?.deepSeconds || 0) / 60), 0) / items.length;

    results.push({
      tag,
      count: items.length,
      hrvDelta: Number((tagHrv - avgHrv).toFixed(1)),
      rhrDelta: Number((tagRhr - avgRhr).toFixed(1)),
      sleepScoreDelta: Number((tagSleep - avgSleep).toFixed(1)),
      deepMinutesDelta: Math.round(tagDeepMin - avgDeepMin)
    });
  }

  return results.sort((a, b) => Math.abs(b.hrvDelta) - Math.abs(a.hrvDelta));
}

export function exportUserData(userId, format = 'json') {
  const summaries = getDailySummariesRange(userId, '2018-01-01', '2099-12-31');
  if (format === 'json') {
    return {
      contentType: 'application/json; charset=utf-8',
      filename: `laura-oura-export-user-${userId}.json`,
      body: JSON.stringify(summaries, null, 2)
    };
  }

  const headers = [
    'day',
    'readiness_score',
    'sleep_score',
    'activity_score',
    'lowest_hr_bpm',
    'average_hrv_ms',
    'temp_deviation_c',
    'total_sleep_min',
    'deep_sleep_min',
    'rem_sleep_min',
    'light_sleep_min',
    'sleep_efficiency_pct',
    'bedtime_start',
    'bedtime_end',
    'steps',
    'active_calories',
    'total_calories',
    'spo2_pct',
    'stress_high_min',
    'recovery_high_min',
    'tags',
    'custom_note'
  ];

  const escapeCsv = (val) => {
    if (val == null) return '';
    const str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const lines = [headers.join(',')];
  for (const s of summaries) {
    lines.push(
      [
        s.day,
        s.readiness?.score,
        s.sleep?.score,
        s.activity?.score,
        s.sleep?.lowestHr,
        s.sleep?.averageHrv,
        s.readiness?.tempDeviation,
        s.sleep?.totalSeconds != null ? Math.round(s.sleep.totalSeconds / 60) : '',
        s.sleep?.deepSeconds != null ? Math.round(s.sleep.deepSeconds / 60) : '',
        s.sleep?.remSeconds != null ? Math.round(s.sleep.remSeconds / 60) : '',
        s.sleep?.lightSeconds != null ? Math.round(s.sleep.lightSeconds / 60) : '',
        s.sleep?.efficiency,
        s.sleep?.bedtimeStart,
        s.sleep?.bedtimeEnd,
        s.activity?.steps,
        s.activity?.activeCalories,
        s.activity?.totalCalories,
        s.spo2?.percentage,
        s.stress?.stressHighSeconds != null ? Math.round(s.stress.stressHighSeconds / 60) : '',
        s.stress?.recoveryHighSeconds != null ? Math.round(s.stress.recoveryHighSeconds / 60) : '',
        (s.tags || []).join('; '),
        s.customNote
      ]
        .map(escapeCsv)
        .join(',')
    );
  }

  return {
    contentType: 'text/csv; charset=utf-8',
    filename: `laura-oura-export-user-${userId}.csv`,
    body: lines.join('\n')
  };
}

// --- Oura Cycle Insights & Biphasic Skin Temperature Engine ---

const PHASE_METADATA = {
  menstrual: {
    key: 'menstrual',
    label: 'Menstrual Phase',
    shortLabel: 'Menstrual',
    color: '#f43f5e',
    hormoneNote: 'Estrogen & progesterone are at baseline. Nightly skin temperature drops back below 0.0°C and RHR lowers.',
    recoveryTip: 'Prioritize restorative sleep, iron-rich nutrition, gentle movement, and warmth.'
  },
  follicular: {
    key: 'follicular',
    label: 'Follicular Phase',
    shortLabel: 'Follicular',
    color: '#6366f1',
    hormoneNote: 'Estrogen rises steadily prior to ovulation. Skin temperature stays cool (-0.10°C to -0.30°C below baseline) with strong HRV.',
    recoveryTip: 'Prime window for high-intensity workouts, strength PRs, and higher training loads.'
  },
  ovulation: {
    key: 'ovulation',
    label: 'Ovulation & Fertile Window',
    shortLabel: 'Ovulation Window',
    color: '#06b6d4',
    hormoneNote: 'Peak estrogen & LH surge followed by a biphasic thermal shift (+0.20°C to +0.45°C rise as progesterone releases).',
    recoveryTip: 'Peak energy and social stamina. Stay well-hydrated as body temperature begins its upward shift.'
  },
  luteal: {
    key: 'luteal',
    label: 'Luteal Phase',
    shortLabel: 'Luteal',
    color: '#a855f7',
    hormoneNote: 'Progesterone dominates, keeping nightly skin temperature elevated (+0.15°C to +0.45°C) and raising RHR by ~2–4 bpm.',
    recoveryTip: 'Higher temperature and slightly lower HRV are normal hormonal shifts (not illness). Favor steady cardio, mobility, and earlier wind-down.'
  },
  untracked: {
    key: 'untracked',
    label: 'Log Period to Start Tracking',
    shortLabel: 'Not Logged Yet',
    color: '#64748b',
    hormoneNote: 'Log your most recent period start date below to unlock biphasic ring temperature & cycle phase predictions.',
    recoveryTip: 'Oura Ring 3 measures overnight skin temperature at ±0.01°C resolution to detect follicular and luteal phases.'
  }
};

function buildMemberCycleBrief(userId, targetDay) {
  const logs = getCycleLogsForUser(userId, '2000-01-01', targetDay);
  const bleedingLogs = logs.filter((l) => ['light', 'medium', 'heavy'].includes(l.flow));
  if (bleedingLogs.length === 0) return null;
  const insights = computeCycleInsights(userId, targetDay, 30);
  if (!insights.hasCycleData) return null;
  return {
    cycleDay: insights.currentCycleDay,
    phase: insights.currentPhase,
    daysUntilNextPeriod: insights.predictions.daysUntilNextPeriod,
    tempDeviation: insights.todayLog?.tempDeviation ?? null
  };
}

export function computeCycleInsights(userId, targetDay, days = 60) {
  const startWindow = subtractDays(targetDay, Math.max(days, 120));
  const summaries = getDailySummariesRange(userId, startWindow, targetDay);
  const summaryByDay = new Map(summaries.map((s) => [s.day, s]));

  const allLogs = getCycleLogsForUser(userId, '2000-01-01', addDays(targetDay, 30));
  const logByDay = new Map(allLogs.map((l) => [l.day, l]));

  // 1. Group bleeding days (light/medium/heavy) into distinct period episodes (gap > 3 days = new period)
  const bleedingDays = allLogs
    .filter((l) => ['light', 'medium', 'heavy'].includes(l.flow))
    .map((l) => l.day)
    .sort();

  const periods = [];
  for (const d of bleedingDays) {
    const last = periods[periods.length - 1];
    if (!last || daysBetween(last.endDay, d) > 3) {
      periods.push({
        startDay: d,
        endDay: d,
        days: [d]
      });
    } else {
      last.endDay = d;
      last.days.push(d);
    }
  }

  // 2. Build cycle history & detect biphasic 3-over-6 thermal shift per cycle
  const cycles = periods.map((p, idx) => {
    const nextPeriod = periods[idx + 1] || null;
    const rawLen = nextPeriod ? daysBetween(p.startDay, nextPeriod.startDay) : null;
    const cycleLength = rawLen && rawLen >= 18 && rawLen <= 45 ? rawLen : null;
    const periodLength = daysBetween(p.startDay, p.endDay) + 1;

    // Scan days 8..24 of this cycle for a 3-over-6 temperature shift (+0.18°C above prior 6-day mean)
    const searchMaxDay = Math.min(cycleLength ? cycleLength - 3 : 24, 25);
    let detectedOvulationDay = null;
    let detectedOvulationCycleDay = null;
    let confirmedByTemp = false;

    for (let cd = 10; cd <= searchMaxDay; cd++) {
      const candDay = addDays(p.startDay, cd - 1);
      const log = logByDay.get(candDay);
      if (log?.ovulationTest === 'positive') {
        detectedOvulationDay = candDay;
        detectedOvulationCycleDay = cd;
        confirmedByTemp = true;
        break;
      }

      // Check 3 consecutive elevated nights starting at cd + 1 compared to 6 nights before cd + 1
      const prev6 = [];
      for (let k = cd - 5; k <= cd; k++) {
        const s = summaryByDay.get(addDays(p.startDay, k - 1));
        if (s?.readiness?.tempDeviation != null) prev6.push(s.readiness.tempDeviation);
      }
      const next3 = [];
      for (let k = cd + 1; k <= cd + 3; k++) {
        const s = summaryByDay.get(addDays(p.startDay, k - 1));
        if (s?.readiness?.tempDeviation != null) next3.push(s.readiness.tempDeviation);
      }
      if (prev6.length >= 4 && next3.length === 3) {
        const meanPrev6 = prev6.reduce((a, b) => a + b, 0) / prev6.length;
        const all3Higher = next3.every((v) => v >= meanPrev6 + 0.15);
        const meanNext3 = next3.reduce((a, b) => a + b, 0) / 3;
        if (all3Higher && meanNext3 - meanPrev6 >= 0.2) {
          detectedOvulationDay = candDay;
          detectedOvulationCycleDay = cd;
          confirmedByTemp = true;
          break;
        }
      }
    }

    const estOvulationCycleDay = detectedOvulationCycleDay || Math.max(10, (cycleLength || 28) - 14);
    const estOvulationDay = detectedOvulationDay || addDays(p.startDay, estOvulationCycleDay - 1);

    // Compute follicular vs luteal temperature means for this cycle
    const folTemps = [];
    const lutTemps = [];
    const spanDays = cycleLength || Math.min(32, Math.max(1, daysBetween(p.startDay, targetDay) + 1));
    for (let cd = 1; cd <= spanDays; cd++) {
      const s = summaryByDay.get(addDays(p.startDay, cd - 1));
      const t = s?.readiness?.tempDeviation;
      if (t != null) {
        if (cd <= estOvulationCycleDay) folTemps.push(t);
        else lutTemps.push(t);
      }
    }
    const folMean = folTemps.length ? folTemps.reduce((a, b) => a + b, 0) / folTemps.length : null;
    const lutMean = lutTemps.length ? lutTemps.reduce((a, b) => a + b, 0) / lutTemps.length : null;
    const thermalShiftC =
      folMean != null && lutMean != null ? Number((lutMean - folMean).toFixed(2)) : null;

    return {
      startDay: p.startDay,
      endDay: nextPeriod ? subtractDays(nextPeriod.startDay, 1) : null,
      periodEndDay: p.endDay,
      periodLength,
      cycleLength,
      ovulationDay: estOvulationDay,
      ovulationCycleDay: estOvulationCycleDay,
      lutealLength: cycleLength ? cycleLength - estOvulationCycleDay : null,
      confirmedByTemp,
      follicularTempC: folMean != null ? Number(folMean.toFixed(2)) : null,
      lutealTempC: lutMean != null ? Number(lutMean.toFixed(2)) : null,
      thermalShiftC
    };
  });

  const completedCycles = cycles.filter((c) => c.cycleLength != null);
  const avgCycleLength = completedCycles.length
    ? Math.round(completedCycles.reduce((a, c) => a + c.cycleLength, 0) / completedCycles.length)
    : 28;
  const avgPeriodLength = cycles.length
    ? Math.round(cycles.reduce((a, c) => a + c.periodLength, 0) / cycles.length)
    : 5;

  let cycleVariationDays = 0;
  if (completedCycles.length >= 2) {
    const lens = completedCycles.map((c) => c.cycleLength);
    cycleVariationDays = Number(((Math.max(...lens) - Math.min(...lens)) / 2).toFixed(1));
  }

  // Helper to resolve cycle day & phase for any calendar date
  const resolveDayPhase = (dayStr) => {
    const log = logByDay.get(dayStr);
    const activeCycles = cycles.filter((c) => c.startDay <= dayStr);
    const curCycle = activeCycles[activeCycles.length - 1] || null;
    if (!curCycle) {
      return {
        cycleDay: null,
        phase: 'untracked',
        isOvulationDay: false,
        isPeriodStart: false
      };
    }
    const cd = daysBetween(curCycle.startDay, dayStr) + 1;
    if (cd > 45) {
      return {
        cycleDay: cd,
        phase: 'untracked',
        isOvulationDay: false,
        isPeriodStart: false
      };
    }
    const ovCd = curCycle.ovulationCycleDay || Math.max(10, avgCycleLength - 14);
    const isBleeding = log && ['light', 'medium', 'heavy'].includes(log.flow);
    let phase = 'follicular';
    if (isBleeding || cd <= curCycle.periodLength) {
      phase = 'menstrual';
    } else if (cd >= ovCd - 4 && cd <= ovCd + 1) {
      phase = 'ovulation';
    } else if (cd > ovCd + 1) {
      phase = 'luteal';
    }
    return {
      cycleDay: cd,
      phase,
      isOvulationDay: cd === ovCd,
      isPeriodStart: dayStr === curCycle.startDay,
      confirmedByTemp: curCycle.confirmedByTemp
    };
  };

  // Current cycle state on targetDay
  const targetState = resolveDayPhase(targetDay);
  const currentPhaseMeta = PHASE_METADATA[targetState.phase] || PHASE_METADATA.untracked;
  const activeCyclesUpToTarget = cycles.filter((c) => c.startDay <= targetDay);
  const currentCycle = activeCyclesUpToTarget[activeCyclesUpToTarget.length - 1] || null;

  const nextPeriodDate = currentCycle ? addDays(currentCycle.startDay, avgCycleLength) : null;
  const daysUntilNextPeriod = nextPeriodDate ? daysBetween(targetDay, nextPeriodDate) : null;
  const estOvulationCycleDay = currentCycle?.ovulationCycleDay || Math.max(10, avgCycleLength - 14);
  const nextOvulationDate = currentCycle
    ? addDays(currentCycle.startDay, estOvulationCycleDay - 1)
    : null;
  const fertileWindowStart = nextOvulationDate ? subtractDays(nextOvulationDate, 4) : null;
  const fertileWindowEnd = nextOvulationDate ? addDays(nextOvulationDate, 1) : null;

  // Build timeline for chart (days ending at targetDay)
  const chartStartDay = subtractDays(targetDay, days - 1);
  const timeline = [];
  const folStats = { temps: [], rhrs: [], hrvs: [], sleeps: [] };
  const lutStats = { temps: [], rhrs: [], hrvs: [], sleeps: [] };

  for (let i = 0; i < days; i++) {
    const d = addDays(chartStartDay, i);
    const s = summaryByDay.get(d);
    const l = logByDay.get(d);
    const st = resolveDayPhase(d);
    const tempDev = s?.readiness?.tempDeviation ?? null;
    const rhr = s?.sleep?.lowestHr ?? null;
    const hrv = s?.sleep?.averageHrv ?? null;
    const sleepScore = s?.sleep?.score ?? null;

    if (st.phase === 'menstrual' || st.phase === 'follicular' || st.phase === 'ovulation') {
      if (tempDev != null) folStats.temps.push(tempDev);
      if (rhr != null) folStats.rhrs.push(rhr);
      if (hrv != null) folStats.hrvs.push(hrv);
      if (sleepScore != null) folStats.sleeps.push(sleepScore);
    } else if (st.phase === 'luteal') {
      if (tempDev != null) lutStats.temps.push(tempDev);
      if (rhr != null) lutStats.rhrs.push(rhr);
      if (hrv != null) lutStats.hrvs.push(hrv);
      if (sleepScore != null) lutStats.sleeps.push(sleepScore);
    }

    timeline.push({
      day: d,
      cycleDay: st.cycleDay,
      phase: st.phase,
      isOvulationDay: st.isOvulationDay,
      isOvulationConfirmed: st.isOvulationDay && st.confirmedByTemp,
      isPeriodStart: st.isPeriodStart,
      tempDeviation: tempDev,
      rhr,
      hrv,
      sleepScore,
      readinessScore: s?.readiness?.score ?? null,
      flow: l?.flow || 'none',
      symptoms: l?.symptoms || [],
      ovulationTest: l?.ovulationTest || 'none',
      notes: l?.notes || ''
    });
  }

  // Compute 3-day rolling temperature trend on timeline
  for (let i = 0; i < timeline.length; i++) {
    const win = [timeline[i - 2], timeline[i - 1], timeline[i]]
      .filter((x) => x && x.tempDeviation != null)
      .map((x) => x.tempDeviation);
    const rollingVal = win.length
      ? Number((win.reduce((a, b) => a + b, 0) / win.length).toFixed(2))
      : null;
    timeline[i].tempTrend = rollingVal;
    timeline[i].rollingTemp3d = rollingVal;
  }

  const mean = (arr, dec = 1) =>
    arr.length ? Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(dec)) : null;

  const folTempAvg = mean(folStats.temps, 2);
  const lutTempAvg = mean(lutStats.temps, 2);
  const thermalShiftDelta =
    folTempAvg != null && lutTempAvg != null ? Number((lutTempAvg - folTempAvg).toFixed(2)) : null;
  const rawDayLog = getCycleLog(userId, targetDay);
  const selectedDayLog = {
    userId,
    day: targetDay,
    flow: rawDayLog?.flow || 'none',
    symptoms: rawDayLog?.symptoms || [],
    ovulationTest: rawDayLog?.ovulationTest || 'none',
    notes: rawDayLog?.notes || ''
  };
  const todayItem = timeline[timeline.length - 1] || selectedDayLog;

  const normalizedPhase = {
    ...currentPhaseMeta,
    hormoneSummary: currentPhaseMeta.hormoneSummary || currentPhaseMeta.hormoneNote || ''
  };

  const reversedHistory = [...cycles].reverse().slice(0, 6).map((c, idx) => ({
    ...c,
    cycleNumber: cycles.length - idx,
    isCurrent: idx === 0,
    cycleLength: c.cycleLength || daysBetween(c.startDay, targetDay) + 1,
    thermalShiftDeltaC: c.thermalShiftC
  }));

  return {
    user: getUserById(userId),
    userId,
    day: targetDay,
    hasCycleData: cycles.length > 0,
    currentCycleDay: targetState.cycleDay,
    currentPhase: normalizedPhase,
    confirmedByTemp: Boolean(currentCycle?.confirmedByTemp),
    currentCycle: currentCycle
      ? {
          cycleStartDay: currentCycle.startDay,
          cycleDay: targetState.cycleDay,
          avgCycleLength,
          avgPeriodLength,
          cycleVariabilityDays: cycleVariationDays,
          regularityLabel: cycleVariationDays <= 2.5 ? 'Regular' : 'Moderate Variation',
          phase: normalizedPhase,
          predictedNextPeriodStart: nextPeriodDate,
          daysUntilNextPeriod,
          fertileWindow: {
            start: fertileWindowStart,
            end: fertileWindowEnd,
            ovulationDay: nextOvulationDate,
            ovulationCycleDay: estOvulationCycleDay,
            thermalShiftDeltaC: currentCycle.thermalShiftC ?? thermalShiftDelta,
            detectedBy: currentCycle.confirmedByTemp
              ? 'Oura Ring Biphasic Temp Shift (3-over-6)'
              : 'Calendar & Luteal Baseline Estimate',
            isInFertileWindow:
              Boolean(fertileWindowStart && fertileWindowEnd && targetDay >= fertileWindowStart && targetDay <= fertileWindowEnd)
          }
        }
      : null,
    predictions: {
      avgCycleLength,
      avgPeriodLength,
      cycleVariationDays,
      regularityLabel: cycleVariationDays <= 2.5 ? 'Regular' : 'Variable',
      nextPeriodDate,
      daysUntilNextPeriod,
      ovulationDate: nextOvulationDate,
      ovulationCycleDay: estOvulationCycleDay,
      fertileWindowStart,
      fertileWindowEnd
    },
    phaseComparison: {
      follicular: {
        tempDeviation: folTempAvg,
        lowestHr: mean(folStats.rhrs, 1),
        averageHrv: mean(folStats.hrvs, 0),
        sleepScore: mean(folStats.sleeps, 0)
      },
      luteal: {
        tempDeviation: lutTempAvg,
        lowestHr: mean(lutStats.rhrs, 1),
        averageHrv: mean(lutStats.hrvs, 0),
        sleepScore: mean(lutStats.sleeps, 0)
      },
      thermalShiftDelta
    },
    selectedDayLog,
    todayLog: todayItem,
    cycleHistory: reversedHistory,
    cyclesHistory: reversedHistory,
    timeline
  };
}
