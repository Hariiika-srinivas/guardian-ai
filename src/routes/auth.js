require('dotenv').config();
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { query } = require('../config/database');

const router = express.Router();

// ── REGISTER ──────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { full_name, phone_number, email, password, age, gender } = req.body;

    if (!full_name || !phone_number || !password) {
      return res.status(400).json({ error: 'full_name, phone_number and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const [existing] = await query(
      'SELECT id FROM users WHERE phone_number = ?',
      [phone_number]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Phone number already registered' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 12);

    // Get a UUID from MySQL
    const [uuidRow] = await query('SELECT UUID() as id');
    const userId = uuidRow[0].id;
    const firebase_uid = 'demo_' + userId;

    // Insert user
    await query(
      `INSERT INTO users 
        (id, firebase_uid, full_name, phone_number, email, password_hash, age, gender)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, firebase_uid, full_name, phone_number,
       email || null, password_hash, age || null, gender || null]
    );

    // Create JWT token
    const token = jwt.sign(
      { id: userId, phone_number, full_name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: userId, full_name, phone_number }
    });

  } catch (error) {
    console.error('Register error:', error.message);
    return res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { phone_number, password } = req.body;

    if (!phone_number || !password) {
      return res.status(400).json({ error: 'phone_number and password are required' });
    }

    const [rows] = await query(
      'SELECT id, full_name, phone_number, email, password_hash FROM users WHERE phone_number = ?',
      [phone_number]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid phone number or password' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ error: 'Invalid phone number or password' });
    }

    const token = jwt.sign(
      { id: user.id, phone_number: user.phone_number, full_name: user.full_name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, full_name: user.full_name, phone_number: user.phone_number }
    });

  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// ── GET MY PROFILE ────────────────────────────────────────────
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token' });
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const [rows] = await query(
      'SELECT id, full_name, phone_number, email, created_at FROM users WHERE id = ?',
      [decoded.id]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: rows[0] });

  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;