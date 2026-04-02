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

let SITE_PASSWORD = process.env.SITE_PASSWORD || 'NL1!';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'NLAdmin!';

function hashPw(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

// Password protection middleware
app.use(express.json({ limit: '10mb' }));
app.use(require('cookie-parser')());

function checkAuth(req, res, next) {
  if (req.path === '/login' || req.path === '/login.html') return next();
  const token = req.cookies?.nlauth;
  if (token === hashPw(ADMIN_PASSWORD) || token === hashPw(SITE_PASSWORD)) return next();
  if (req.path.startsWith('/api/') || req.path.startsWith('/socket.io/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.send(loginPage());
}

function isAdmin(req) {
  return req.cookies?.nlauth === hashPw(ADMIN_PASSWORD);
}

app.post('/login', express.urlencoded({ extended: false }), (req, res) => {
  const pw = req.body.password;
  if (pw === ADMIN_PASSWORD) {
    res.cookie('nlauth', hashPw(ADMIN_PASSWORD), { httpOnly: true, sameSite: 'lax' });
    return res.redirect('/');
  }
  if (pw === SITE_PASSWORD) {
    res.cookie('nlauth', hashPw(SITE_PASSWORD), { httpOnly: true, sameSite: 'lax' });
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

// ═══ INIT DB ═══
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_log (
      id SERIAL PRIMARY KEY,
      ts TIMESTAMPTZ DEFAULT NOW(),
      action TEXT NOT NULL,
      detail TEXT,
      shift_key TEXT,
      user_type TEXT DEFAULT 'user'
    )
  `);
}

// ═══ ACTIVITY LOG HELPER ═══
async function logActivity(action, detail, shiftKey, userType) {
  try {
    await pool.query(
      'INSERT INTO activity_log (action, detail, shift_key, user_type) VALUES ($1, $2, $3, $4)',
      [action, detail || null, shiftKey || null, userType || 'user']
    );
  } catch (e) { console.error('Log error:', e.message); }
}

// ═══ AUTH ENDPOINTS ═══
app.get('/api/auth/me', (req, res) => {
  res.json({ admin: isAdmin(req) });
});

// ═══ ADMIN ENDPOINTS ═══

// Get connected user count
app.get('/api/admin/users', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  res.json({ count: io.engine.clientsCount });
});

// Change site password
app.post('/api/admin/password', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 3) {
    return res.status(400).json({ error: 'Password must be at least 3 characters' });
  }
  SITE_PASSWORD = newPassword;
  logActivity('password-change', 'Site password changed', null, 'admin');
  res.json({ ok: true });
});

// Delete a shift (admin only)
app.delete('/api/admin/shifts/:key', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    await pool.query('DELETE FROM shifts WHERE key = $1', [req.params.key]);
    logActivity('shift-delete', `Deleted shift: ${req.params.key}`, req.params.key, 'admin');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get activity log (admin only)
app.get('/api/admin/log', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query(
      'SELECT * FROM activity_log ORDER BY ts DESC LIMIT 100'
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Set announcement (admin only)
app.post('/api/admin/announce', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const { message, type } = req.body; // type: info, warning, danger
  io.emit('announcement', { message: message || '', type: type || 'info' });
  logActivity('announcement', message || '(cleared)', null, 'admin');
  res.json({ ok: true });
});

// Lock/unlock a shift (admin only)
app.post('/api/admin/lock', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const { key, locked } = req.body;
  io.emit('shift-lock', { key, locked: !!locked });
  logActivity(locked ? 'shift-lock' : 'shift-unlock', `Shift: ${key}`, key, 'admin');
  res.json({ ok: true });
});

// Force refresh all clients (admin only)
app.post('/api/admin/refresh', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  io.emit('force-refresh');
  logActivity('force-refresh', 'All clients refreshed', null, 'admin');
  res.json({ ok: true });
});

// Get shift stats (admin only)
app.get('/api/admin/stats', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('SELECT key, data, updated_at FROM shifts ORDER BY key DESC LIMIT 60');
    const stats = [];
    for (const row of result.rows) {
      const d = row.data;
      let totalUnits = 0, complete = 0, stopped = 0, overdue = 0, avgDays = 0, daysList = [];
      // Count units in roads
      if (d.roads) {
        for (const bays of Object.values(d.roads)) {
          for (const bay of Object.values(bays)) {
            if (bay && bay.unit) {
              totalUnits++;
              if (bay.status === 'COMPLETE') complete++;
              if (bay.status === 'STOPPED') stopped++;
              if (bay.sched_release) {
                const diff = (new Date() - new Date(bay.sched_release)) / 86400000;
                if (diff > 1) overdue++;
              }
              if (bay.arrtime) {
                const days = Math.max(0, Math.floor((new Date() - new Date(bay.arrtime)) / 86400000));
                daysList.push(days);
              }
            }
          }
        }
      }
      // Count sub sheds
      if (d.subSheds) {
        for (const bays of Object.values(d.subSheds)) {
          for (const bay of Object.values(bays)) {
            if (bay && bay.unit) {
              totalUnits++;
              if (bay.status === 'COMPLETE') complete++;
              if (bay.status === 'STOPPED') stopped++;
            }
          }
        }
      }
      if (d.svcRoads) {
        for (const bays of Object.values(d.svcRoads)) {
          for (const bay of Object.values(bays)) {
            if (bay && bay.unit) {
              totalUnits++;
              if (bay.status === 'COMPLETE') complete++;
              if (bay.status === 'STOPPED') stopped++;
            }
          }
        }
      }
      avgDays = daysList.length ? (daysList.reduce((a, b) => a + b, 0) / daysList.length).toFixed(1) : 0;
      const awaitingCount = (d.awaiting || []).length;
      const staffCount = (() => {
        const sm = d.staffMatrix || {};
        let c = 0;
        ['lv4elec','lv4mech','gwl','vb','lv3','tri','caf'].forEach(k => {
          if (sm[k]) c += sm[k].filter(v => v && v.trim()).length;
        });
        return c;
      })();

      stats.push({
        key: row.key,
        updated: row.updated_at,
        totalUnits,
        complete,
        stopped,
        overdue,
        avgDays: parseFloat(avgDays),
        awaitingCount,
        staffCount
      });
    }
    res.json(stats);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Export shift data as JSON (for PDF/Excel generation client-side)
app.get('/api/admin/export/:key', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await pool.query('SELECT data, updated_at FROM shifts WHERE key = $1', [req.params.key]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    logActivity('export', `Exported shift: ${req.params.key}`, req.params.key, 'admin');
    res.json({ key: req.params.key, data: result.rows[0].data, updated: result.rows[0].updated_at });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ FLEET MANAGEMENT (admin only) ═══
app.get('/api/admin/fleet', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const fleet = require('./public/fleet.json');
    res.json(fleet);
  } catch (e) {
    res.json({});
  }
});

app.put('/api/admin/fleet', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const fs = require('fs');
    fs.writeFileSync(path.join(__dirname, 'public', 'fleet.json'), JSON.stringify(req.body, null, 2));
    logActivity('fleet-update', 'Fleet database updated', null, 'admin');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ SHIFT ENDPOINTS ═══
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

app.put('/api/shifts/:key', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO shifts (key, data, updated_at) VALUES ($1, $2, NOW())
      ON CONFLICT (key) DO UPDATE SET data = $2, updated_at = NOW()
    `, [req.params.key, req.body]);
    io.emit('shift-updated', { key: req.params.key });
    logActivity('shift-save', null, req.params.key, isAdmin(req) ? 'admin' : 'user');
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/shifts', async (req, res) => {
  try {
    const result = await pool.query('SELECT key FROM shifts ORDER BY key DESC');
    res.json(result.rows.map(r => r.key));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ CONFIG ENDPOINTS ═══
app.get('/api/config/:key', async (req, res) => {
  try {
    const result = await pool.query('SELECT data FROM config WHERE key = $1', [req.params.key]);
    if (result.rows.length === 0) return res.json(null);
    res.json(result.rows[0].data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

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

// ═══ SEARCH ═══
app.get('/api/search', async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase();
    if (!q || q.length < 2) return res.json([]);
    const result = await pool.query('SELECT key, data FROM shifts ORDER BY key DESC LIMIT 90');
    const hits = [];
    for (const row of result.rows) {
      const d = row.data;
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
      // Search service shed roads
      if (d.svcRoads) {
        for (const [roadName, bays] of Object.entries(d.svcRoads)) {
          for (const [bayNum, bay] of Object.entries(bays)) {
            if (!bay) continue;
            const text = JSON.stringify(bay).toLowerCase();
            if (text.includes(q)) {
              hits.push({ key: row.key, type: 'svc', id: roadName, bay: parseInt(bayNum), unit: bay.unit, detail: [bay.worktype, bay.status, bay.team, bay.comments].filter(Boolean).join(' · ') });
            }
          }
        }
      }
      if (d.awaiting) {
        for (const aw of d.awaiting) {
          const text = JSON.stringify(aw).toLowerCase();
          if (text.includes(q)) {
            hits.push({ key: row.key, type: 'awaiting', id: null, bay: null, unit: aw.unit, detail: [aw.reason, aw.currentLoc, aw.update].filter(Boolean).join(' · ') });
          }
        }
      }
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

// ═══ SOCKET.IO ═══
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  io.emit('user-count', { count: io.engine.clientsCount });
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    io.emit('user-count', { count: io.engine.clientsCount });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  await initDB();
  console.log(`Server running on port ${PORT}`);
});
