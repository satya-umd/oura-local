import {
  listHouseholdUsers,
  createUser,
  getRawUserByUsername,
  upsertDailySummary,
  replaceHeartrateDay,
  upsertWorkout,
  upsertCycleLog,
  getCycleLogsForUser,
  addSyncLog,
  setUserSyncState,
  getSetting,
  setSetting,
  toLocalDayStr
} from './db.mjs';
import { hashPassword } from './security.mjs';

function seededRandom(seed) {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function getMayaCycleDayForOffset(offset) {
  // Anchor cycle so today (offset = 0) is Cycle Day 19 (Luteal Phase, 5 days post-ovulation)
  // Period starts occurred at offset = 18, 46, 74
  const daysSinceAnchor = 74 - offset;
  const mod = ((daysSinceAnchor % 28) + 28) % 28;
  return mod + 1; // 1..28
}

export function seedMayaCycleLogs(userId, days = 90) {
  const today = new Date();
  for (let offset = days - 1; offset >= 0; offset--) {
    const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - offset, 12, 0, 0);
    const dayStr = toLocalDayStr(d);
    const cycleDay = getMayaCycleDayForOffset(offset);
    if (cycleDay === 1) {
      upsertCycleLog(userId, dayStr, {
        flow: 'medium',
        symptoms: ['Cramps', 'Fatigue'],
        ovulationTest: 'none',
        notes: 'Cycle Day 1 — period started.'
      });
    } else if (cycleDay === 2) {
      upsertCycleLog(userId, dayStr, {
        flow: 'heavy',
        symptoms: ['Cramps', 'Lower Back Ache'],
        ovulationTest: 'none',
        notes: 'Cycle Day 2 — heavier flow.'
      });
    } else if (cycleDay === 3) {
      upsertCycleLog(userId, dayStr, {
        flow: 'medium',
        symptoms: ['Fatigue'],
        ovulationTest: 'none',
        notes: ''
      });
    } else if (cycleDay === 4 || cycleDay === 5) {
      upsertCycleLog(userId, dayStr, {
        flow: 'light',
        symptoms: [],
        ovulationTest: 'none',
        notes: ''
      });
    } else if (cycleDay === 13) {
      upsertCycleLog(userId, dayStr, {
        flow: 'none',
        symptoms: ['High Energy'],
        ovulationTest: 'positive',
        notes: 'Positive LH surge strip.'
      });
    } else if (cycleDay === 26) {
      upsertCycleLog(userId, dayStr, {
        flow: 'none',
        symptoms: ['Bloating', 'Breast Tenderness'],
        ovulationTest: 'none',
        notes: 'Late luteal phase.'
      });
    }
  }
}

function generateHypnogramAndCurves(totalBuckets, baseHr, baseHrv, rand) {
  let hypno = '';
  const hrSeries = [];
  const hrvSeries = [];

  for (let i = 0; i < totalBuckets; i++) {
    const progress = i / totalBuckets;
    const r = rand();
    let stage = '2'; // Light
    if (i < 2 || i === totalBuckets - 1 || (r < 0.045 && i > 8)) {
      stage = '4'; // Awake
    } else if (progress < 0.45 && r < 0.36) {
      stage = '1'; // Deep sleep concentrated in first half
    } else if (progress > 0.35 && r < 0.34) {
      stage = '3'; // REM sleep concentrated in second half
    } else if (r < 0.14) {
      stage = '1';
    }
    hypno += stage;

    // Nighttime HR curve dips in middle-late night, slightly higher during REM/Awake
    const uShape = Math.sin(progress * Math.PI) * -4.2;
    const stageOffset = stage === '4' ? 7 : stage === '3' ? 2.5 : stage === '1' ? -1.8 : 0;
    const hr = Math.round(clamp(baseHr + 4 + uShape + stageOffset + (rand() - 0.5) * 3, 42, 88));
    hrSeries.push(hr);

    // Nighttime HRV rises toward morning
    const hrvRise = progress * 12;
    const hrvStage = stage === '1' ? 5 : stage === '4' ? -10 : 0;
    const hrv = Math.round(clamp(baseHrv - 5 + hrvRise + hrvStage + (rand() - 0.5) * 10, 20, 125));
    hrvSeries.push(hrv);
  }

  return { hypno, hrSeries, hrvSeries };
}

function generateIntradayHrSamples(dayStr, baseRhr, hasWorkout, rand) {
  const samples = [];
  const [y, m, d] = dayStr.split('-').map(Number);
  for (let mins = 0; mins < 1440; mins += 15) {
    const hh = Math.floor(mins / 60);
    const mm = mins % 60;
    const timestamp = new Date(y, m - 1, d, hh, mm, 0).toISOString();
    const hour = mins / 60;

    let bpm = baseRhr + 16;
    let source = 'awake';

    if (hour < 6.75 || hour >= 23.0) {
      source = 'sleep';
      bpm = baseRhr + 3 + Math.sin((hour / 7) * Math.PI) * -3 + (rand() - 0.5) * 4;
    } else if (hasWorkout && hour >= 17.25 && hour <= 18.25) {
      source = 'workout';
      bpm = 132 + (rand() - 0.5) * 26;
    } else if (hour >= 13 && hour <= 14.5) {
      source = 'rest';
      bpm = baseRhr + 9 + (rand() - 0.5) * 5;
    } else {
      source = 'awake';
      bpm = baseRhr + 19 + Math.sin(((hour - 7) / 15) * Math.PI) * 8 + (rand() - 0.5) * 10;
    }

    samples.push({
      timestamp,
      bpm: Math.round(clamp(bpm, 43, 178)),
      source
    });
  }
  return samples;
}

export function seedDemoHousehold({ days = 90, force = false } = {}) {
  const existingUsers = listHouseholdUsers();
  if (existingUsers.length > 0 && !force) {
    // Ensure Maya has demo cycle logs seeded if she is still in demo mode and has no cycle logs yet
    const mayaExisting = existingUsers.find((u) => u.username === 'maya');
    if (mayaExisting && !mayaExisting.hasLiveToken) {
      const existingLogs = getCycleLogsForUser(mayaExisting.id);
      if (existingLogs.length === 0) {
        seedMayaCycleLogs(mayaExisting.id, days);
      }
    }
    return { seeded: false, users: existingUsers };
  }

  const defaultPassHash = hashPassword('laura2026');

  let user1 = getRawUserByUsername('alex');
  if (!user1) {
    user1 = createUser({
      username: 'alex',
      displayName: 'Alex (My Ring)',
      email: 'alex@household.local',
      passwordHash: defaultPassHash,
      role: 'admin',
      avatarColor: '#6366f1',
      ringName: 'Oura Ring Gen 3 • Heritage Black',
      shareWithHousehold: 1,
      authMode: 'demo'
    });
  }

  let user2 = getRawUserByUsername('maya');
  if (!user2) {
    user2 = createUser({
      username: 'maya',
      displayName: 'Maya (Wife)',
      email: 'maya@household.local',
      passwordHash: defaultPassHash,
      role: 'member',
      avatarColor: '#ec4899',
      ringName: 'Oura Ring Gen 3 • Horizon Rose Gold',
      shareWithHousehold: 1,
      authMode: 'demo'
    });
  }

  const profiles = [
    {
      id: user1.id,
      seed: 104729,
      baseRhr: 51,
      baseHrv: 64,
      baseBedHour: 22.6, // ~10:36 PM
      baseSleepHrs: 7.6,
      baseSteps: 9400
    },
    {
      id: user2.id,
      seed: 209351,
      baseRhr: 55,
      baseHrv: 72,
      baseBedHour: 22.35, // ~10:21 PM
      baseSleepHrs: 7.9,
      baseSteps: 8900
    }
  ];

  const today = new Date();

  for (const prof of profiles) {
    const currentInfo = listHouseholdUsers().find((u) => u.id === prof.id);
    if (currentInfo?.hasLiveToken) {
      // Never overwrite a user who has connected their live Oura Ring!
      continue;
    }
    const rand = seededRandom(prof.seed);

    for (let offset = days - 1; offset >= 0; offset--) {
      const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - offset, 12, 0, 0);
      const dayStr = toLocalDayStr(d);
      const prevDay = new Date(d.getFullYear(), d.getMonth(), d.getDate() - 1, 12, 0, 0);
      const prevDayStr = toLocalDayStr(prevDay);

      const dayOfWeek = d.getDay();
      const isWeekend = dayOfWeek === 5 || dayOfWeek === 6;

      // Pick realistic lifestyle tags
      const tags = [];
      let tagHrvEffect = 0;
      let tagRhrEffect = 0;
      let tagDeepEffectMin = 0;

      const tagRoll = rand();
      if (tagRoll < 0.22) {
        tags.push('Magnesium');
        tagHrvEffect += 7;
        tagRhrEffect -= 1.5;
        tagDeepEffectMin += 14;
      }
      if (rand() < 0.16) {
        tags.push('Sauna');
        tagHrvEffect += 6;
        tagRhrEffect -= 1.0;
        tagDeepEffectMin += 11;
      }
      if (isWeekend && rand() < 0.35) {
        tags.push('Late meal');
        tagHrvEffect -= 9;
        tagRhrEffect += 3.5;
        tagDeepEffectMin -= 16;
      }
      if (isWeekend && rand() < 0.24) {
        tags.push('Wine');
        tagHrvEffect -= 13;
        tagRhrEffect += 4.8;
        tagDeepEffectMin -= 19;
      }
      if (!isWeekend && rand() < 0.25) {
        tags.push('Morning sunlight');
        tagHrvEffect += 4;
        tagDeepEffectMin += 7;
      }

      // Bedtime hour (21.2 to 25.2)
      const bedtimeHour = clamp(
        prof.baseBedHour + (isWeekend ? 0.65 : 0) + (rand() - 0.5) * 1.4,
        21.2,
        25.3
      );

      // Earlier bedtime improves deep sleep and HRV
      const bedtimePenalty = bedtimeHour - 22.5; // positive if late
      const totalSleepHours = clamp(
        prof.baseSleepHrs - bedtimePenalty * 0.28 + (isWeekend ? 0.35 : 0) + (rand() - 0.5) * 0.9,
        5.8,
        9.2
      );
      const totalSleepSeconds = Math.round(totalSleepHours * 3600);
      const awakeSeconds = Math.round(clamp((18 + rand() * 28) * 60, 600, 3600));
      const timeInBedSeconds = totalSleepSeconds + awakeSeconds;

      const deepMinutes = clamp(
        Math.round(92 - bedtimePenalty * 14 + tagDeepEffectMin + (rand() - 0.5) * 20),
        38,
        150
      );
      const deepSleepSeconds = deepMinutes * 60;
      const remSleepSeconds = Math.round(clamp(totalSleepSeconds * (0.21 + (rand() - 0.5) * 0.05), 2700, 8400));
      const lightSleepSeconds = Math.max(3600, totalSleepSeconds - deepSleepSeconds - remSleepSeconds);

      const isMaya = prof.id === user2.id;
      const cycleDay = isMaya ? getMayaCycleDayForOffset(offset) : null;
      const isLutealNight = isMaya && cycleDay >= 15;
      const cycleRhrShift = isMaya ? (isLutealNight ? 2.4 : -1.1) : 0;
      const cycleHrvShift = isMaya ? (isLutealNight ? -6 : 4) : 0;

      const sleepEfficiency = Math.round((totalSleepSeconds / timeInBedSeconds) * 100);
      const lowestHr = Math.round(
        clamp(prof.baseRhr + cycleRhrShift + bedtimePenalty * 1.6 + tagRhrEffect + (rand() - 0.5) * 2.8, 44, 68)
      );
      const averageHr = Number((lowestHr + 5.2 + rand() * 2.4).toFixed(1));
      const averageHrv = Math.round(
        clamp(prof.baseHrv + cycleHrvShift - bedtimePenalty * 5.5 + tagHrvEffect + (rand() - 0.5) * 10, 32, 108)
      );
      const averageBreath = Number((14.2 + (rand() - 0.5) * 1.4).toFixed(1));

      // Compute Bedtime Start and End ISO strings in local device clock time
      const [py, pm, pd] = prevDayStr.split('-').map(Number);
      const bedDate = new Date(py, pm - 1, pd, 0, Math.round(bedtimeHour * 60), 0);
      const wakeDate = new Date(bedDate.getTime() + timeInBedSeconds * 1000);

      const totalBuckets = Math.max(40, Math.round(timeInBedSeconds / 300));
      const { hypno, hrSeries, hrvSeries } = generateHypnogramAndCurves(
        totalBuckets,
        lowestHr,
        averageHrv,
        rand
      );

      const sleepScore = Math.round(
        clamp(
          55 +
            (totalSleepHours - 6.0) * 11 +
            (deepMinutes - 60) * 0.22 +
            (sleepEfficiency - 85) * 0.6,
          56,
          97
        )
      );

      const hrvContrib = Math.round(clamp(75 + (averageHrv - prof.baseHrv) * 0.9, 52, 98));
      const rhrContrib = Math.round(clamp(82 - (lowestHr - prof.baseRhr) * 3.5, 48, 98));
      const recoveryContrib = Math.round(clamp(78 + (rand() - 0.4) * 18, 55, 97));
      const sleepBalanceContrib = Math.round(clamp(sleepScore - 2 + (rand() - 0.5) * 8, 55, 97));
      const activityBalanceContrib = Math.round(clamp(80 + (rand() - 0.5) * 14, 60, 96));

      const readinessScore = Math.round(
        clamp(
          hrvContrib * 0.25 +
            rhrContrib * 0.22 +
            sleepScore * 0.25 +
            recoveryContrib * 0.15 +
            activityBalanceContrib * 0.13,
          54,
          96
        )
      );

      let tempDeviation;
      if (isMaya && cycleDay) {
        // Biphasic Oura Ring 3 temperature profile:
        // Follicular (Day 1..14): cooler (-0.12 to -0.28 °C), nadir around Day 13-14
        // Luteal (Day 15..28): sustained progesterone thermal shift (+0.18 to +0.38 °C)
        const basePhaseTemp =
          cycleDay <= 12
            ? -0.17
            : cycleDay <= 14
              ? -0.24
              : cycleDay <= 26
                ? 0.27
                : 0.12;
        tempDeviation = Number(clamp(basePhaseTemp + (rand() - 0.5) * 0.09, -0.38, 0.48).toFixed(2));
      } else {
        tempDeviation = Number(
          clamp((lowestHr - prof.baseRhr) * 0.03 + (rand() - 0.5) * 0.22, -0.35, 0.48).toFixed(2)
        );
      }

      const hasWorkout = rand() < 0.48;
      const steps = Math.round(
        clamp(prof.baseSteps + (hasWorkout ? 3100 : -600) + (rand() - 0.5) * 3400, 3800, 17500)
      );
      const activeCalories = Math.round(steps * 0.046 + (hasWorkout ? 240 : 40));
      const totalCalories = 1850 + activeCalories + Math.round((rand() - 0.5) * 180);
      const activityScore = Math.round(clamp(68 + (steps / 10000) * 18 + (rand() - 0.5) * 8, 58, 97));

      const spo2Percentage = Number(clamp(97.8 + (rand() - 0.5) * 1.8, 95.4, 99.6).toFixed(1));
      const stressHighSeconds = Math.round(clamp((45 + (bedtimePenalty > 0.5 ? 30 : 0) + rand() * 75) * 60, 900, 9600));
      const recoveryHighSeconds = Math.round(clamp((65 + (tagHrvEffect > 0 ? 35 : 0) + rand() * 80) * 60, 1800, 10800));
      const stressSummary =
        recoveryHighSeconds >= stressHighSeconds
          ? 'restored'
          : stressHighSeconds > recoveryHighSeconds * 1.35
            ? 'stressful'
            : 'normal';

      let customNote = '';
      if (offset === 0) {
        customNote =
          prof.id === user1.id
            ? 'Felt well-rested after early wind-down and magnesium.'
            : 'Great deep sleep last night, morning walk together.';
      } else if (offset === 2) {
        customNote = 'Evening sauna session helped lower RHR.';
      }

      upsertDailySummary(prof.id, dayStr, {
        readiness_score: readinessScore,
        temp_deviation: tempDeviation,
        temp_trend_deviation: Number((tempDeviation * 0.7).toFixed(2)),
        hrv_balance_contrib: hrvContrib,
        resting_hr_contrib: rhrContrib,
        recovery_index_contrib: recoveryContrib,
        sleep_balance_contrib: sleepBalanceContrib,
        previous_night_contrib: sleepScore,
        activity_balance_contrib: activityBalanceContrib,
        sleep_score: sleepScore,
        total_sleep_seconds: totalSleepSeconds,
        deep_sleep_seconds: deepSleepSeconds,
        rem_sleep_seconds: remSleepSeconds,
        light_sleep_seconds: lightSleepSeconds,
        awake_seconds: awakeSeconds,
        time_in_bed_seconds: timeInBedSeconds,
        sleep_efficiency: sleepEfficiency,
        sleep_latency_seconds: Math.round((9 + rand() * 14) * 60),
        lowest_hr: lowestHr,
        average_hr: averageHr,
        average_hrv: averageHrv,
        average_breath: averageBreath,
        bedtime_start: bedDate.toISOString(),
        bedtime_end: wakeDate.toISOString(),
        hypnogram_5min: hypno,
        hr_5min_json: JSON.stringify(hrSeries),
        hrv_5min_json: JSON.stringify(hrvSeries),
        activity_score: activityScore,
        steps,
        active_calories: activeCalories,
        total_calories: totalCalories,
        equivalent_walking_distance: Math.round(steps * 0.76),
        high_activity_seconds: hasWorkout ? Math.round((25 + rand() * 30) * 60) : Math.round(rand() * 10 * 60),
        medium_activity_seconds: Math.round((35 + rand() * 40) * 60),
        low_activity_seconds: Math.round((160 + rand() * 80) * 60),
        sedentary_seconds: Math.round((460 + rand() * 90) * 60),
        inactivity_alerts: rand() < 0.3 ? 1 : 0,
        spo2_percentage: spo2Percentage,
        breathing_disturbance_index: Number((0.4 + rand() * 1.1).toFixed(1)),
        stress_high_seconds: stressHighSeconds,
        recovery_high_seconds: recoveryHighSeconds,
        stress_day_summary: stressSummary,
        tags_json: JSON.stringify(tags),
        custom_note: customNote
      });

      if (hasWorkout) {
        const activities = ['Running', 'Strength Training', 'Cycling', 'Yoga & Mobility', 'Hiking'];
        const act = activities[Math.floor(rand() * activities.length)];
        const [wy, wm, wd] = dayStr.split('-').map(Number);
        upsertWorkout(prof.id, {
          id: `demo-workout-${prof.id}-${dayStr}`,
          day: dayStr,
          activity: act,
          calories: Math.round(220 + rand() * 260),
          distance: act === 'Running' || act === 'Cycling' || act === 'Hiking' ? Math.round(3500 + rand() * 5000) : 0,
          start_datetime: new Date(wy, wm - 1, wd, 17, 15, 0).toISOString(),
          end_datetime: new Date(wy, wm - 1, wd, 18, 5, 0).toISOString(),
          intensity: rand() > 0.4 ? 'moderate' : 'high'
        });
      }

      // Generate 24h intraday HR for recent 14 days
      if (offset <= 14) {
        const samples = generateIntradayHrSamples(dayStr, lowestHr, hasWorkout, rand);
        replaceHeartrateDay(prof.id, dayStr, samples);
      }
    }

    if (prof.id === user2.id) {
      seedMayaCycleLogs(user2.id, days);
    }

    const nowIso = new Date().toISOString();
    setUserSyncState(prof.id, { status: 'ok', lastSyncedAt: nowIso, error: null });
    addSyncLog(prof.id, {
      startedAt: nowIso,
      finishedAt: nowIso,
      status: 'success',
      daysSynced: days,
      message: `Initialized ${days} days of Oura Ring Gen 3 history.`
    });
  }

  // Lock public registration once the 2 household accounts exist
  if (getSetting('registration_locked') === null) {
    setSetting('registration_locked', true);
  }
  if (getSetting('household_name') === null) {
    setSetting('household_name', 'Alex & Maya Household');
  }

  return { seeded: true, users: listHouseholdUsers() };
}

// Allow running directly via `npm run seed`
if (import.meta.url === `file://${process.argv[1]}`) {
  const result = seedDemoHousehold({ days: 90, force: true });
  console.log(`Seeded ${result.users.length} household users with 90 days of Oura Ring 3 data.`);
}
