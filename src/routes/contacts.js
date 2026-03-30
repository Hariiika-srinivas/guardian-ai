const express   = require('express');
const jwt       = require('jsonwebtoken');
const { query } = require('../config/database');

const router = express.Router();

// Middleware — checks token on every request to this router
function auth(req, res, next) {
  try {
    const header = req.headers['authorization'];
    if (!header) return res.status(401).json({ error: 'No token provided' });
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── ADD CONTACT ───────────────────────────────────────────────
router.post('/', auth, async (req, res) => {
  try {
    const { full_name, phone_number, relationship, priority } = req.body;
    const userId = req.user.id;

    if (!full_name || !phone_number || !priority) {
      return res.status(400).json({ error: 'full_name, phone_number and priority required' });
    }

    if (![1, 2, 3].includes(Number(priority))) {
      return res.status(400).json({ error: 'Priority must be 1, 2, or 3' });
    }

    const [existing] = await query(
      'SELECT COUNT(*) as count FROM emergency_contacts WHERE user_id = ?',
      [userId]
    );
    if (existing[0].count >= 3) {
      return res.status(400).json({ error: 'Maximum 3 emergency contacts allowed' });
    }

    const [uuidRow] = await query('SELECT UUID() as id');
    const contactId = uuidRow[0].id;

    await query(
      `INSERT INTO emergency_contacts (id, user_id, full_name, phone_number, relationship, priority)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [contactId, userId, full_name, phone_number, relationship || null, Number(priority)]
    );

    return res.status(201).json({
      message: 'Emergency contact added',
      contact: { id: contactId, full_name, phone_number, relationship, priority }
    });

  } catch (error) {
    console.error('Add contact error:', error.message);
    return res.status(500).json({ error: 'Failed to add contact: ' + error.message });
  }
});

// ── LIST CONTACTS ─────────────────────────────────────────────
router.get('/', auth, async (req, res) => {
  try {
    const [contacts] = await query(
      `SELECT id, full_name, phone_number, relationship, priority, is_verified
       FROM emergency_contacts WHERE user_id = ? ORDER BY priority ASC`,
      [req.user.id]
    );
    return res.json({ contacts });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to get contacts' });
  }
});

// ── DELETE CONTACT ────────────────────────────────────────────
router.delete('/:id', auth, async (req, res) => {
  try {
    const [result] = await query(
      'DELETE FROM emergency_contacts WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }
    return res.json({ message: 'Contact removed' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to delete contact' });
  }
});

module.exports = router;