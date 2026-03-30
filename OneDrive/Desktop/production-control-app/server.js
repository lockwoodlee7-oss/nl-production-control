const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Init DB table
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shifts (
      key TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      data JSONB NOT NULL
    )
  `);
}

// GET shift data
app.get('/api/shifts/:key', async (req, res) => {
  try {
    const result = await pool.query('SELECT data FROM shifts WHERE key = $1', [req.params.key]);
    if (result.rows.length === 0) return res.json(null);
    res.json(result.rows[0].data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// PUT shift data
app.put('/api/shifts/:key', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO shifts (key, data, updated_at) VALUES ($1, $2, NOW())
      ON CONFLICT (key) DO UPDATE SET data = $2, updated_at = NOW()
    `, [req.params.key, req.body]);
    io.emit('shift-updated', { key: req.params.key });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// GET all shift keys
app.get('/api/shifts', async (req, res) => {
  try {
    const result = await pool.query('SELECT key FROM shifts ORDER BY key DESC');
    res.json(result.rows.map(r => r.key));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET config (links, handover template)
app.get('/api/config/:key', async (req, res) => {
  try {
    const result = await pool.query('SELECT data FROM config WHERE key = $1', [req.params.key]);
    if (result.rows.length === 0) return res.json(null);
    res.json(result.rows[0].data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT config
app.put('/api/config/:key', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO config (key, data) VALUES ($1, $2)
      ON CONFLICT (key) DO UPDATE SET data = $2
    `, [req.params.key, req.body]);
    io.emit('config-updated', { key: req.params.key });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// SEARCH across all shifts
app.get('/api/search', async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase();
    if (!q || q.length < 2) return res.json([]);
    const result = await pool.query('SELECT key, data FROM shifts ORDER BY key DESC LIMIT 90');
    const hits = [];
    for (const row of result.rows) {
      const d = row.data;
      // Search roads
      if (d.roads) {
        for (const [roadNum, bays] of Object.entries(d.roads)) {
          for (const [bayNum, bay] of Object.entries(bays)) {
            if (!bay) continue;
            const text = JSON.stringify(bay).toLowerCase();
            if (text.includes(q)) {
              hits.push({ key: row.key, type: 'road', id: roadNum, bay: parseInt(bayNum), unit: bay.unit, detail: bay.job || bay.notes || '' });
            }
          }
        }
      }
      // Search handover notes
      if (d.handover) {
        for (const [label, val] of Object.entries(d.handover)) {
          if (val && val.toLowerCase().includes(q)) {
            hits.push({ key: row.key, type: 'notes', id: null, bay: null, unit: null, detail: val.slice(0, 80) });
            break;
          }
        }
      }
    }
    res.json(hits.slice(0, 30));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve index.html for everything else
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('disconnect', () => console.log('Client disconnected:', socket.id));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  await initDB();
  console.log(`Server running on port ${PORT}`);
});
