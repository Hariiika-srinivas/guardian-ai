const express        = require('express');
const jwt            = require('jsonwebtoken');
const { query }      = require('../config/database');
const twilio         = require('twilio');

const router = express.Router();

// Initialize Twilio
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

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

// ── TRIGGER ALERT ─────────────────────────────────────────────
router.post('/trigger', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { threat_event_id, latitude, longitude, threat_score } = req.body;

    // Get user
    const [users] = await query(
      'SELECT full_name, phone_number FROM users WHERE id = ?',
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = users[0];

    // Get emergency contacts
    const [contacts] = await query(
      `SELECT id, full_name, phone_number, priority
       FROM emergency_contacts WHERE user_id = ? ORDER BY priority ASC`,
      [userId]
    );

    if (contacts.length === 0) {
      return res.status(400).json({
        error: 'No emergency contacts found. Please add contacts first.'
      });
    }

    const locationText = latitude && longitude
      ? `${latitude}, ${longitude}`
      : 'Location unavailable';

    const results = [];

    // Send SMS to ALL contacts
    for (const contact of contacts) {
      try {
        const sms = await twilioClient.messages.create({
          body:
            `🚨 GUARDIAN AI EMERGENCY ALERT 🚨\n\n` +
            `${user.full_name} may be in DANGER!\n\n` +
            `Threat Score: ${threat_score || 85}/100\n` +
            `Location: ${locationText}\n` +
            `Maps: https://maps.google.com/?q=${locationText}\n\n` +
            `Please call them IMMEDIATELY.\n\n` +
            `— Guardian AI Safety System`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to:   contact.phone_number
        });

        results.push({
          contact: contact.full_name,
          phone: contact.phone_number,
          sms: 'sent',
          sms_sid: sms.sid
        });

        // Log it
        const [logId] = await query('SELECT UUID() as id');
        await query(
          `INSERT INTO alert_logs
            (id, threat_event_id, user_id, contact_id,
             alert_type, phone_number, status, twilio_sid)
           VALUES (?, ?, ?, ?, 'sms', ?, 'sent', ?)`,
          [logId[0].id, threat_event_id || null, userId,
           contact.id, contact.phone_number, sms.sid]
        );

      } catch (smsError) {
        console.error('SMS error:', smsError.message);
        results.push({
          contact: contact.full_name,
          phone: contact.phone_number,
          sms: 'failed',
          error: smsError.message
        });
      }
    }

    // Make VOICE CALL to priority 1 contact
    const primary = contacts[0];
    try {
      const twiml =
        `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    This is an automated emergency alert from Guardian AI.
  </Say>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    ${user.full_name} may be in danger and needs immediate help.
  </Say>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    Their last known location is ${locationText}.
  </Say>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    The Guardian AI threat detection system has flagged abnormal 
    biometric readings combined with an isolated location at night.
  </Say>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    Please call ${user.full_name} immediately or go to their location.
  </Say>
  <Pause length="1"/>
  <Say voice="alice" language="en-IN">
    This message is from Guardian AI. Stay safe.
  </Say>
</Response>`;

      const call = await twilioClient.calls.create({
        twiml: twiml,
        from:  process.env.TWILIO_PHONE_NUMBER,
        to:    primary.phone_number
      });

      results.push({
        contact: primary.full_name,
        phone:   primary.phone_number,
        call:    'initiated',
        call_sid: call.sid
      });

      // Log the call
      const [callLogId] = await query('SELECT UUID() as id');
      await query(
        `INSERT INTO alert_logs
          (id, threat_event_id, user_id, contact_id,
           alert_type, phone_number, status, twilio_sid)
         VALUES (?, ?, ?, ?, 'call', ?, 'initiated', ?)`,
        [callLogId[0].id, threat_event_id || null, userId,
         primary.id, primary.phone_number, call.sid]
      );

    } catch (callError) {
      console.error('Call error:', callError.message);
      results.push({
        contact: primary.full_name,
        call: 'failed',
        error: callError.message
      });
    }

    // Update threat event status
    if (threat_event_id) {
      await query(
        `UPDATE threat_events SET status = 'alert_sent' WHERE id = ?`,
        [threat_event_id]
      );
    }

    return res.json({
      message: 'Emergency alert triggered',
      user: user.full_name,
      location: locationText,
      contacts_alerted: contacts.length,
      results
    });

  } catch (error) {
    console.error('Alert trigger error:', error.message);
    return res.status(500).json({ error: 'Alert failed: ' + error.message });
  }
});

// ── USER CONFIRMS SAFE ────────────────────────────────────────
router.post('/safe', auth, async (req, res) => {
  try {
    const { threat_event_id } = req.body;
    if (threat_event_id) {
      await query(
        `UPDATE threat_events
         SET status = 'resolved_safe', resolved_at = NOW()
         WHERE id = ? AND user_id = ?`,
        [threat_event_id, req.user.id]
      );
    }
    return res.json({ message: 'Glad you are safe! Alert cancelled.' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update status' });
  }
});

// ── TWILIO WEBHOOK ────────────────────────────────────────────
router.post('/call-response', (req, res) => {
  const digit = req.body.Digits;
  let text = 'We did not receive a response. Please call them directly.';
  if (digit === '1') text = 'Thank you. Please go help them immediately.';
  if (digit === '2') text = 'Thank you. Please contact the local authorities immediately.';

  res.type('text/xml');
  res.send(
    `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice" language="en-IN">${text}</Say>
</Response>`
  );
});

module.exports = router;