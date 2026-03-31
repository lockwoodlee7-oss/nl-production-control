const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const path = require('path');

const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'NL1!';

// Password protection middleware
app.use(express.json({ limit: '10mb' }));
app.use(require('cookie-parser')());

function checkAuth(req, res, next) {
  // Allow login page and login POST through
  if (req.path === '/login' || req.path === '/login.html') return next();
  // Check auth cookie
  const token = req.cookies?.nlauth;
  const expected = crypto.createHash('sha256').update(SITE_PASSWORD).digest('hex');
  if (token === expected) return next();
  // Not authed — serve login page
  if (req.path.startsWith('/api/') || req.path.startsWith('/socket.io/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.send(loginPage());
}

app.post('/login', express.urlencoded({ extended: false }), (req, res) => {
  if (req.body.password === SITE_PASSWORD) {
    const token = crypto.createHash('sha256').update(SITE_PASSWORD).digest('hex');
    res.cookie('nlauth', token, { httpOnly: true, sameSite: 'lax' });
    return res.redirect('/');
  }
  return res.send(loginPage('Incorrect password'));
});

function loginPage(error) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Login — Neville Hill TCC</title>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700;800;900&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Barlow Condensed',sans-serif;background:#0d1017;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#161b26;border:1px solid #232a38;border-radius:14px;padding:40px;width:360px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.logo{width:60px;height:60px;background:#fff;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-weight:900;font-size:22px;color:#1a1f3a;margin-bottom:16px}
h1{color:#fff;font-size:20px;font-weight:800;letter-spacing:2px;margin-bottom:4px}
.sub{color:rgba(255,255,255,.3);font-size:10px;letter-spacing:1.5px;margin-bottom:24px}
input{width:100%;padding:12px 14px;border-radius:8px;border:1px solid #232a38;background:#0d1017;color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:14px;outline:none;margin-bottom:12px;text-align:center;letter-spacing:2px}
input:focus{border-color:#f4793b}
button{width:100%;padding:12px;border-radius:8px;border:none;background:#f4793b;color:#fff;font-family:'Barlow Condensed',sans-serif;font-size:14px;font-weight:800;letter-spacing:1px;cursor:pointer}
button:hover{opacity:.85}
.err{color:#f87171;font-size:12px;margin-bottom:12px;font-weight:700}
</style></head><body>
<div class="box">
<div class="logo">NL</div>
<h1>PRODUCTION CONTROL</h1>
<div class="sub">NEVILLE HILL — REPAIR SHED OPERATIONS</div>
${error ? `<div class="err">${error}</div>` : ''}
<form method="POST" action="/login">
<input type="password" name="password" placeholder="Enter password" autofocus>
<button type="submit">LOGIN</button>
</form>
</div></body></html>`;
}

app.use(checkAuth);
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
              hits.push({ key: row.key, type: 'road', id: roadNum, bay: parseInt(bayNum), unit: bay.unit, detail: [bay.worktype, bay.status, bay.team, bay.comments].filter(Boolean).join(' · ') });
            }
          }
        }
      }
      // Search sub sheds
      if (d.subSheds) {
        for (const [shedName, bays] of Object.entries(d.subSheds)) {
          for (const [bayNum, bay] of Object.entries(bays)) {
            if (!bay) continue;
            const text = JSON.stringify(bay).toLowerCase();
            if (text.includes(q)) {
              hits.push({ key: row.key, type: 'sub', id: shedName, bay: parseInt(bayNum), unit: bay.unit, detail: [bay.worktype, bay.status, bay.team, bay.comments].filter(Boolean).join(' · ') });
            }
          }
        }
      }
      // Search awaiting list
      if (d.awaiting) {
        for (const aw of d.awaiting) {
          const text = JSON.stringify(aw).toLowerCase();
          if (text.includes(q)) {
            hits.push({ key: row.key, type: 'awaiting', id: null, bay: null, unit: aw.unit, detail: [aw.reason, aw.currentLoc, aw.update].filter(Boolean).join(' · ') });
          }
        }
      }
      // Search handover notes
      if (d.handover) {
        for (const [label, val] of Object.entries(d.handover)) {
          if (val && val.toLowerCase().includes(q)) {
            hits.push({ key: row.key, type: 'notes', id: null, bay: null, unit: null, detail: label + ': ' + val.slice(0, 80) });
            break;
          }
        }
      }
    }
    res.json(hits.slice(0, 50));
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
