require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const path      = require('path');

const { testConnection } = require('./src/config/database');
const authRoutes    = require('./src/routes/auth');
const contactRoutes = require('./src/routes/contacts');
const threatRoutes  = require('./src/routes/threat');
const alertRoutes   = require('./src/routes/alert');

const app  = express();
const PORT = process.env.PORT || 3000;

// NO helmet — it was blocking the demo page scripts
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Guardian AI Backend' });
});

// Serve demo frontend
app.use('/demo', express.static(path.join(__dirname, 'demo')));
app.get('/demo', (req, res) => {
  res.sendFile(path.join(__dirname, 'demo', 'index.html'));
});

// API routes
app.use('/api/v1/auth',     authRoutes);
app.use('/api/v1/contacts', contactRoutes);
app.use('/api/v1/threat',   threatRoutes);
app.use('/api/v1/alert',    alertRoutes);

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start
async function startServer() {
  try {
    console.log('🔄 Connecting to MySQL...');
    await testConnection();
    console.log('✅ MySQL connected');

    app.listen(PORT, () => {
      console.log('');
      console.log('🛡️  Guardian AI is running');
      console.log(`✅  http://localhost:${PORT}`);
      console.log(`🔍  http://localhost:${PORT}/health`);
      console.log(`🎯  http://localhost:${PORT}/demo`);
      console.log('');
    });
  } catch (error) {
    console.error('❌ Failed to start:', error.message);
    process.exit(1);
  }
}

startServer();