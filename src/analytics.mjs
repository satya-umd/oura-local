import {
  listHouseholdUsers,
  getDailySummary,
  getDailySummariesRange,
  getUserBaselines
} from './db.mjs';

function subtractDays(dayStr, numDays) {
  const d = new Date(`${dayStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() - numDays);
  return d.toISOString().slice(0, 10);
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
