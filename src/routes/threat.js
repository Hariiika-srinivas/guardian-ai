const express   = require('express');
const jwt       = require('jsonwebtoken');
const { query } = require('../config/database');

const router = express.Router();

function auth(req, res, next) {
  try {
    const header = req.headers['authorization'];
    if (!header) return res.status(401).json({ error: 'No token' });
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── THE AI THREAT ENGINE ──────────────────────────────────────
function analyzeThreat(data) {
  const {
    heart_rate, accel_variance, is_isolated,
    ambient_db, speed_mps, baseline_hr,
    activity_context, hour_of_day
  } = data;

  let score = 0;
  const reasons = [];

  // SIGNAL 1: Heart rate — compare to baseline, not fixed number
  if (heart_rate && baseline_hr) {
    const rise = ((heart_rate - baseline_hr) / baseline_hr) * 100;

    if (activity_context === 'exercise') {
      // Exercise mode — even 200% rise = 0 points. No false alerts.
      score += 0;
    } else if (rise >= 80 && activity_context === 'resting') {
      score += 35;
      reasons.push(`Heart rate ${heart_rate}BPM — ${Math.round(rise)}% above baseline while resting`);
    } else if (rise >= 60) {
      score += 20;
      reasons.push(`Heart rate ${heart_rate}BPM — ${Math.round(rise)}% above baseline`);
    } else if (rise >= 40) {
      score += 10;
      reasons.push(`Heart rate elevated — ${Math.round(rise)}% above baseline`);
    }
  }

  // SIGNAL 2: Movement — erratic vs rhythmic
  // Exercise = low variance (steady rhythm)
  // Danger = high variance (struggling, sudden movements)
  if (accel_variance !== undefined) {
    if (accel_variance > 2.0 && activity_context !== 'exercise') {
      score += 20;
      reasons.push('Sudden erratic body movement detected');
    } else if (accel_variance > 1.5 && activity_context !== 'exercise') {
      score += 10;
      reasons.push('Abnormal movement pattern detected');
    } else if (accel_variance < 0.5 && activity_context === 'exercise') {
      score -= 5; // Rhythmic = definitely exercise, reduce score
    }
  }

  // SIGNAL 3: Isolated location
  if (is_isolated) {
    const isNight = hour_of_day < 6 || hour_of_day > 21;
    if (isNight) {
      score += 25;
      reasons.push('Isolated location during nighttime hours');
    } else {
      score += 8;
      reasons.push('Isolated location detected');
    }
  }

  // SIGNAL 4: Loud sound — screaming, impact
  if (ambient_db) {
    if (ambient_db > 90) {
      score += 20;
      reasons.push(`Loud sound detected — ${ambient_db}dB`);
    } else if (ambient_db > 75 && activity_context !== 'exercise') {
      score += 8;
      reasons.push('Elevated ambient noise');
    }
  }

  // SIGNAL 5: Fast movement in isolated area = panic run
  if (speed_mps > 5.0 && is_isolated) {
    score += 15;
    reasons.push('Running fast in isolated area');
  }

  // SIGNAL 6: Late night adds baseline risk
  if (hour_of_day < 5 || hour_of_day > 22) {
    score += 10;
    reasons.push('Late night — elevated baseline risk');
  }

  // EXERCISE OVERRIDE: If exercise mode, remove 75% of all points
  // This is the key protection against false alerts during workouts
  if (activity_context === 'exercise') {
    score = Math.round(score * 0.25);
    if (score > 0) reasons.push('[Exercise mode active — score reduced by 75%]');
  }

  // Clamp 0–100
  score = Math.max(0, Math.min(100, score));

  let level, action;
  if (score < 30)      { level = 'low';      action = 'monitor'; }
  else if (score < 50) { level = 'medium';   action = 'monitor'; }
  else if (score < 65) { level = 'high';     action = 'checkin'; }
  else                 { level = 'critical'; action = 'alert';   }

  return { score, level, action, reasons };
}

// ── ANALYZE ENDPOINT ──────────────────────────────────────────
router.post('/analyze', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      heart_rate, accel_x, accel_y, accel_z, accel_variance,
      latitude, longitude, speed_mps, is_isolated,
      ambient_db, battery_level, baseline_hr, activity_context
    } = req.body;

    const hour_of_day = new Date().getHours();

    // Save raw sensor reading
    const [uuidRow] = await query('SELECT UUID() as id');
    const readingId = uuidRow[0].id;

    await query(
      `INSERT INTO sensor_readings
        (id, user_id, heart_rate, accel_x, accel_y, accel_z,
         latitude, longitude, speed_mps, is_isolated, ambient_db, battery_level)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [readingId, userId,
       heart_rate || null, accel_x || null, accel_y || null, accel_z || null,
       latitude || null, longitude || null, speed_mps || null,
       is_isolated ? 1 : 0, ambient_db || null, battery_level || null]
    );

    // Run AI analysis
    const assessment = analyzeThreat({
      heart_rate, accel_variance: accel_variance || 0,
      is_isolated, ambient_db, speed_mps,
      baseline_hr: baseline_hr || 70,
      activity_context: activity_context || 'unknown',
      hour_of_day
    });

    // If threat detected, save threat event
    let threatEventId = null;
    if (assessment.score >= 50) {
      const [teUuid] = await query('SELECT UUID() as id');
      threatEventId = teUuid[0].id;
      const location = latitude ? `${latitude},${longitude}` : 'Unknown';

      await query(
        `INSERT INTO threat_events
          (id, user_id, threat_score, threat_level, trigger_reasons,
           latitude, longitude, address, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'detected')`,
        [threatEventId, userId, assessment.score, assessment.level,
         JSON.stringify(assessment.reasons),
         latitude || null, longitude || null, location]
      );
    }

    return res.json({
      reading_id: readingId,
      assessment: { ...assessment, threat_event_id: threatEventId }
    });

  } catch (error) {
    console.error('Threat analyze error:', error.message);
    return res.status(500).json({ error: 'Analysis failed: ' + error.message });
  }
});

// ── HISTORY ───────────────────────────────────────────────────
router.get('/history', auth, async (req, res) => {
  try {
    const [events] = await query(
      `SELECT id, threat_score, threat_level, trigger_reasons,
              address, status, created_at
       FROM threat_events WHERE user_id = ?
       ORDER BY created_at DESC LIMIT 20`,
      [req.user.id]
    );
    return res.json({ events });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to get history' });
  }
});

module.exports = router;