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
// Initial registration password — anyone who knows this can self-register a new
// account (their own first name + last name + clock card number). After first
// login they are forced to set a personal password and this initial password
// stops working for them. Effectively a one-time enrollment token.
const INITIAL_PASSWORD = process.env.INITIAL_PASSWORD || 'NL1!';
// Legacy shared-password login is OFF by default in this version. Admin can
// re-enable from the admin panel if needed during transition.
let ALLOW_LEGACY_PASSWORD = process.env.ALLOW_LEGACY_PASSWORD === 'true';

// Bump this string to force-rotate the session secret and log everyone out.
// Done once per deploy when this changes; subsequent restarts skip rotation.
const SESSION_ROTATION_KEY = '_session_rotation_2026_04_v2';

// ── Legacy password hash (single-shared-password mode, kept for backwards compat) ──
function hashLegacy(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

// ── Per-user password hashing (PBKDF2-SHA512, FIPS-approved) ──
// 210,000 iterations meets current OWASP guidance for SHA-512.
function pwHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
  return 'pbkdf2$210000$' + salt + '$' + hash;
}
function pwVerify(password, stored) {
  if (!stored) return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iters = parseInt(parts[1], 10);
  const salt = parts[2];
  const expected = parts[3];
  const test = crypto.pbkdf2Sync(password, salt, iters, 64, 'sha512').toString('hex');
  // Constant-time compare
  if (test.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < test.length; i++) diff |= test.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ── Session secret ── HMAC-signed cookie tokens. Persisted in DB so sessions
// survive a server restart. Loaded once at startup, cached in memory.
let SESSION_SECRET = process.env.SESSION_SECRET || null;
async function loadSessionSecret() {
  if (SESSION_SECRET) return SESSION_SECRET;
  // Check if a session rotation has been requested for this deploy.
  // If the rotation key isn't in the config table, regenerate the secret
  // (which invalidates all existing session cookies — forces logout for everyone).
  const rotationCheck = await pool.query('SELECT data FROM config WHERE key = $1', [SESSION_ROTATION_KEY]);
  if (rotationCheck.rows.length === 0) {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO config (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = $2',
      ['_session_secret', { secret: SESSION_SECRET }]
    );
    await pool.query(
      'INSERT INTO config (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = $2',
      [SESSION_ROTATION_KEY, { rotatedAt: new Date().toISOString() }]
    );
    console.log('────────────────────────────────────────────────────────');
    console.log('  SESSION SECRET ROTATED');
    console.log('  All existing sessions have been invalidated.');
    console.log('  Everyone must log in again.');
    console.log('────────────────────────────────────────────────────────');
    return SESSION_SECRET;
  }
  // Normal startup — load existing secret
  const r = await pool.query('SELECT data FROM config WHERE key = $1', ['_session_secret']);
  if (r.rows.length > 0 && r.rows[0].data && r.rows[0].data.secret) {
    SESSION_SECRET = r.rows[0].data.secret;
    return SESSION_SECRET;
  }
  SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  await pool.query(
    'INSERT INTO config (key, data) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET data = $2',
    ['_session_secret', { secret: SESSION_SECRET }]
  );
  return SESSION_SECRET;
}
function makeSessionToken(userId) {
  const iat = Date.now();
  const payload = userId + '.' + iat;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}
function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, iat, sig] = parts;
  if (!/^\d+$/.test(userId) || !/^\d+$/.test(iat)) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(userId + '.' + iat).digest('hex');
  if (sig.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  // 30-day expiry
  if (Date.now() - parseInt(iat, 10) > 30 * 86400000) return null;
  return parseInt(userId, 10);
}

// ── Failed login lockout (in-memory; resets on server restart) ──
const failedAttempts = new Map(); // key -> { count, lockedUntil }
function noteFailedLogin(key) {
  const now = Date.now();
  let r = failedAttempts.get(key);
  if (!r || (r.lockedUntil && now > r.lockedUntil)) r = { count: 0, lockedUntil: 0 };
  r.count++;
  if (r.count >= 5) r.lockedUntil = now + 15 * 60 * 1000; // 15 min
  failedAttempts.set(key, r);
  return r;
}
function isLockedOut(key) {
  const r = failedAttempts.get(key);
  if (!r) return false;
  if (r.lockedUntil && Date.now() < r.lockedUntil) return true;
  return false;
}
function clearFailedLogins(key) { failedAttempts.delete(key); }

// Password protection middleware
app.use(express.json({ limit: '10mb' }));
app.use(require('cookie-parser')());

// Cached lookup of currently-logged-in user (per request)
async function getCurrentUser(req) {
  const token = req.cookies?.nlauth;
  if (!token) return null;
  // New signed-token format
  if (token.split('.').length === 3) {
    const userId = verifySessionToken(token);
    if (!userId) return null;
    try {
      const r = await pool.query('SELECT id, username, first_name, last_name, display_name, is_admin, must_change_password FROM users WHERE id = $1', [userId]);
      if (r.rows.length === 0) return null;
      return {
        id: r.rows[0].id,
        username: r.rows[0].username,
        firstName: r.rows[0].first_name,
        lastName: r.rows[0].last_name,
        displayName: r.rows[0].display_name || ((r.rows[0].first_name || '') + ' ' + (r.rows[0].last_name || '')).trim() || r.rows[0].username,
        isAdmin: !!r.rows[0].is_admin,
        mustChangePassword: !!r.rows[0].must_change_password,
        kind: 'user'
      };
    } catch (e) { console.error('getCurrentUser:', e.message); return null; }
  }
  // Legacy shared-password format (only valid if legacy mode still allowed)
  if (ALLOW_LEGACY_PASSWORD) {
    if (token === hashLegacy(ADMIN_PASSWORD)) return { id: 0, username: 'admin', displayName: 'Legacy Admin', isAdmin: true, mustChangePassword: false, kind: 'legacy' };
    if (token === hashLegacy(SITE_PASSWORD)) return { id: 0, username: 'shared', displayName: 'Shared User', isAdmin: false, mustChangePassword: false, kind: 'legacy' };
  }
  return null;
}

async function checkAuth(req, res, next) {
  if (req.path === '/login' || req.path === '/login.html') return next();
  const user = await getCurrentUser(req);
  if (user) { req.user = user; return next(); }
  if (req.path.startsWith('/api/') || req.path.startsWith('/socket.io/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.send(loginPage());
}

function isAdmin(req) {
  return req.user && req.user.isAdmin;
}

app.post('/login', express.urlencoded({ extended: false }), async (req, res) => {
  const firstName = (req.body.firstName || '').trim();
  const lastName  = (req.body.lastName  || '').trim();
  const clockCardRaw = (req.body.clockCard || '').trim();
  const clockCard = clockCardRaw.toLowerCase();
  const pw = req.body.password || '';
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const lockKey = (clockCard || '_anon_') + '@' + ip;

  if (isLockedOut(lockKey)) {
    return res.send(loginPage('Too many failed attempts. Try again in 15 minutes.'));
  }

  // All four fields are required
  if (!firstName || !lastName || !clockCard || !pw) {
    return res.send(loginPage('Please fill in first name, last name, clock card and password.'));
  }

  // Validate clock card format (alphanumeric, allow dot/dash for the bootstrap "admin" value)
  if (!/^[a-zA-Z0-9._-]{2,40}$/.test(clockCard)) {
    return res.send(loginPage('Clock card number can only contain letters, numbers, dots, dashes and underscores.'));
  }

  try {
    const r = await pool.query(
      'SELECT id, username, first_name, last_name, password_hash, is_admin, must_change_password FROM users WHERE LOWER(username) = $1',
      [clockCard]
    );

    if (r.rows.length > 0) {
      // Existing user — verify identity AND password match
      const u = r.rows[0];
      // Identity check (case-insensitive trim) — prevents one user logging in
      // under another's clock card by accident.
      const fnMatch = (u.first_name || '').trim().toLowerCase() === firstName.toLowerCase();
      const lnMatch = (u.last_name  || '').trim().toLowerCase() === lastName.toLowerCase();
      if (!fnMatch || !lnMatch) {
        noteFailedLogin(lockKey);
        return res.send(loginPage('Identity does not match clock card ' + clockCardRaw + '. Check your name spelling.'));
      }
      if (!pwVerify(pw, u.password_hash)) {
        noteFailedLogin(lockKey);
        return res.send(loginPage('Incorrect password. If you have forgotten it, ask Lee to reset it.'));
      }
      // Success
      clearFailedLogins(lockKey);
      await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [u.id]);
      const token = makeSessionToken(u.id);
      res.cookie('nlauth', token, { httpOnly: true, sameSite: 'lax', secure: req.secure || req.headers['x-forwarded-proto'] === 'https', maxAge: 30 * 86400000 });
      logActivity('login', `${firstName} ${lastName} (${clockCardRaw})`, null, u.is_admin ? 'admin' : 'user', firstName + ' ' + lastName);
      return res.redirect('/');
    }

    // No existing user — only INITIAL_PASSWORD allows self-registration.
    // Deliberately VAGUE error message so we don't leak the initial password
    // to anyone stumbling across the login page.
    if (pw !== INITIAL_PASSWORD) {
      noteFailedLogin(lockKey);
      return res.send(loginPage('Login failed. Check your details and try again. If you do not have an account, contact Lee.'));
    }

    // Self-register
    const display = firstName + ' ' + lastName;
    const ins = await pool.query(
      'INSERT INTO users (username, first_name, last_name, display_name, password_hash, is_admin, must_change_password, created_by) VALUES ($1, $2, $3, $4, $5, FALSE, TRUE, $6) RETURNING id',
      [clockCard, firstName, lastName, display, pwHash(pw), 'self-register']
    );
    const newId = ins.rows[0].id;
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [newId]);
    clearFailedLogins(lockKey);
    const token = makeSessionToken(newId);
    res.cookie('nlauth', token, { httpOnly: true, sameSite: 'lax', secure: req.secure || req.headers['x-forwarded-proto'] === 'https', maxAge: 30 * 86400000 });
    logActivity('register', `${display} (${clockCardRaw}) self-registered`, null, 'user', display);
    return res.redirect('/');
  } catch (e) {
    console.error('Login error:', e.message);
    if (e.code === '23505') {
      return res.send(loginPage('That clock card number is already in use. Try again.'));
    }
    noteFailedLogin(lockKey);
    return res.send(loginPage('Login failed. Please try again or contact Lee.'));
  }
});

// Logout — clears cookie
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('nlauth');
  res.json({ ok: true });
});

function loginPage(error) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Login — Neville Hill TCC</title>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700;800;900&family=Barlow:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Barlow Condensed',sans-serif;background:#0d1017;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.box{background:#161b26;border:1px solid #232a38;border-radius:14px;padding:34px 38px;width:420px;max-width:100%;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.head{text-align:center;margin-bottom:22px}
.logo{width:60px;height:60px;background:#fff;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-weight:900;font-size:22px;color:#1a1f3a;margin-bottom:14px}
h1{color:#fff;font-size:20px;font-weight:800;letter-spacing:2px;margin-bottom:4px}
.sub{color:rgba(255,255,255,.3);font-size:10px;letter-spacing:1.5px}
label{display:block;color:rgba(255,255,255,.5);font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;margin-top:10px;font-family:'Barlow Condensed',sans-serif}
input{width:100%;padding:11px 14px;border-radius:8px;border:1px solid #232a38;background:#0d1017;color:#e2e8f0;font-family:'Barlow',sans-serif;font-size:14px;outline:none}
input:focus{border-color:#f4793b}
input.mono{font-family:'JetBrains Mono',monospace;letter-spacing:1px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{width:100%;padding:13px;border-radius:8px;border:none;background:#f4793b;color:#fff;font-family:'Barlow Condensed',sans-serif;font-size:14px;font-weight:800;letter-spacing:1.5px;cursor:pointer;margin-top:20px;text-transform:uppercase}
button:hover{opacity:.88}
.err{color:#fca5a5;font-size:12px;margin-bottom:12px;font-weight:600;background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.3);border-radius:6px;padding:10px 12px;font-family:'Barlow',sans-serif;line-height:1.5}
</style></head><body>
<div class="box">
<div class="head">
<div class="logo">NL</div>
<h1>PRODUCTION CONTROL</h1>
<div class="sub">NEVILLE HILL — REPAIR SHED OPERATIONS</div>
</div>
${error ? `<div class="err">${error}</div>` : ''}
<form method="POST" action="/login" autocomplete="off">
<div class="row">
<div>
<label>First Name</label>
<input type="text" name="firstName" autocomplete="given-name" autofocus required>
</div>
<div>
<label>Last Name</label>
<input type="text" name="lastName" autocomplete="family-name" required>
</div>
</div>
<label>Clock Card Number</label>
<input type="text" name="clockCard" class="mono" autocomplete="username" required>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password" required>
<button type="submit">LOG IN</button>
</form>
</div></body></html>`;
}

app.use(checkAuth);

// Disable caching on all /api/* responses so browsers can never serve stale data
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

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
  // Per-user accounts table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE,
      must_change_password BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ,
      created_by TEXT
    )
  `);
  // Add first_name, last_name columns for the new login flow
  // (and back-fill the bootstrap admin row so it can still log in)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT`);
  // Activity log: add a column to record WHICH user performed each action
  await pool.query(`ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS user_name TEXT`);
  // Persisted session HMAC secret
  await loadSessionSecret();
  // Bootstrap a default admin user on first run, only if no users exist yet.
  // Login: First Name "Lee" / Last Name "Lockwood" / Clock Card "admin" / Password: ChangeMe1!
  try {
    const r = await pool.query('SELECT COUNT(*)::int AS c FROM users');
    if (r.rows[0].c === 0) {
      const bootstrapPw = process.env.BOOTSTRAP_ADMIN_PASSWORD || 'ChangeMe1!';
      const bootstrapFirst = process.env.BOOTSTRAP_ADMIN_FIRST || 'Lee';
      const bootstrapLast  = process.env.BOOTSTRAP_ADMIN_LAST  || 'Lockwood';
      const bootstrapCard  = process.env.BOOTSTRAP_ADMIN_CARD  || 'admin';
      await pool.query(
        'INSERT INTO users (username, first_name, last_name, display_name, password_hash, is_admin, must_change_password, created_by) VALUES ($1, $2, $3, $4, $5, TRUE, TRUE, $6)',
        [bootstrapCard.toLowerCase(), bootstrapFirst, bootstrapLast, bootstrapFirst + ' ' + bootstrapLast, pwHash(bootstrapPw), 'system']
      );
      console.log('────────────────────────────────────────────────────────');
      console.log('  USERS TABLE INITIALISED');
      console.log('  Bootstrap admin created.');
      console.log('  Login with:');
      console.log('    First Name : ' + bootstrapFirst);
      console.log('    Last Name  : ' + bootstrapLast);
      console.log('    Clock Card : ' + bootstrapCard);
      console.log('    Password   : ' + bootstrapPw);
      console.log('  YOU MUST CHANGE THE PASSWORD ON FIRST LOGIN');
      console.log('────────────────────────────────────────────────────────');
    } else {
      // Back-fill first_name / last_name on the original bootstrap admin
      // so it can still log in via the new flow.
      await pool.query(
        `UPDATE users SET first_name = COALESCE(first_name, $1), last_name = COALESCE(last_name, $2)
         WHERE username = $3 AND (first_name IS NULL OR last_name IS NULL)`,
        ['Lee', 'Lockwood', 'admin']
      );
    }
  } catch (e) {
    console.error('Bootstrap admin error:', e.message);
  }
}

// ═══ ACTIVITY LOG HELPER ═══
async function logActivity(action, detail, shiftKey, userType, userName) {
  try {
    await pool.query(
      'INSERT INTO activity_log (action, detail, shift_key, user_type, user_name) VALUES ($1, $2, $3, $4, $5)',
      [action, detail || null, shiftKey || null, userType || 'user', userName || null]
    );
  } catch (e) { console.error('Log error:', e.message); }
}
// Convenience: pulls username from req.user if available
function logFromReq(req, action, detail, shiftKey) {
  const userName = req.user ? (req.user.displayName || req.user.username || null) : null;
  const userType = req.user && req.user.isAdmin ? 'admin' : 'user';
  return logActivity(action, detail, shiftKey, userType, userName);
}

// ═══ AUTH ENDPOINTS ═══
app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    admin: !!req.user.isAdmin,
    id: req.user.id,
    username: req.user.username,
    displayName: req.user.displayName,
    mustChangePassword: !!req.user.mustChangePassword,
    kind: req.user.kind
  });
});

// Self-service password change (any logged-in user with a real account)
app.post('/api/auth/change-password', async (req, res) => {
  if (!req.user || req.user.kind !== 'user') {
    return res.status(401).json({ error: 'You must be logged in as a real user (not the legacy shared password) to change a password.' });
  }
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  try {
    const r = await pool.query('SELECT password_hash, must_change_password FROM users WHERE id = $1', [req.user.id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    // Skip current-password check if must_change_password is set (admin reset)
    if (!r.rows[0].must_change_password) {
      if (!currentPassword || !pwVerify(currentPassword, r.rows[0].password_hash)) {
        return res.status(403).json({ error: 'Current password is incorrect.' });
      }
    }
    await pool.query(
      'UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
      [pwHash(newPassword), req.user.id]
    );
    logActivity('password-change', `${req.user.username} changed own password`, null, req.user.isAdmin ? 'admin' : 'user');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ ADMIN ENDPOINTS ═══

// Get connected user count (was previously /api/admin/users — moved to avoid clash)
app.get('/api/admin/online', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  res.json({ count: io.engine.clientsCount });
});

// ── User management ──
// List all users
app.get('/api/admin/users', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const r = await pool.query(
      'SELECT id, username, first_name, last_name, display_name, is_admin, must_change_password, created_at, last_login, created_by FROM users ORDER BY last_name ASC, first_name ASC'
    );
    res.json(r.rows.map(u => ({
      id: u.id,
      username: u.username,           // = clock card number
      clockCard: u.username,
      firstName: u.first_name,
      lastName: u.last_name,
      displayName: u.display_name,
      isAdmin: u.is_admin,
      mustChangePassword: u.must_change_password,
      createdAt: u.created_at,
      lastLogin: u.last_login,
      createdBy: u.created_by
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Create a user (admin-driven; users normally self-register on first login)
app.post('/api/admin/users', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const { firstName, lastName, clockCard, password, isAdmin: makeAdmin } = req.body || {};
  if (!firstName || !lastName) {
    return res.status(400).json({ error: 'First name and last name are required' });
  }
  if (!clockCard || !/^[a-zA-Z0-9._-]{2,40}$/.test(clockCard)) {
    return res.status(400).json({ error: 'Clock card must be 2–40 chars, letters/numbers/._- only' });
  }
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Initial password must be at least 4 characters' });
  }
  try {
    const display = firstName.trim() + ' ' + lastName.trim();
    const r = await pool.query(
      'INSERT INTO users (username, first_name, last_name, display_name, password_hash, is_admin, must_change_password, created_by) VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7) RETURNING id',
      [clockCard.toLowerCase(), firstName.trim(), lastName.trim(), display, pwHash(password), !!makeAdmin, req.user?.displayName || req.user?.username || 'admin']
    );
    logFromReq(req, 'user-create', `Created ${display} (${clockCard})` + (makeAdmin ? ' as admin' : ''));
    res.json({ ok: true, id: r.rows[0].id });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Clock card already in use' });
    res.status(500).json({ error: e.message });
  }
});

// Update a user (rename, toggle admin)
app.put('/api/admin/users/:id', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const id = parseInt(req.params.id, 10);
  const { displayName, isAdmin: makeAdmin } = req.body || {};
  // Prevent admin from removing their own admin flag (would lock them out)
  if (req.user && req.user.id === id && makeAdmin === false) {
    return res.status(400).json({ error: 'You cannot remove your own admin rights' });
  }
  try {
    await pool.query(
      'UPDATE users SET display_name = COALESCE($1, display_name), is_admin = COALESCE($2, is_admin) WHERE id = $3',
      [displayName ?? null, typeof makeAdmin === 'boolean' ? makeAdmin : null, id]
    );
    logActivity('user-update', `Updated user id ${id}`, null, 'admin');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Reset a user's password (forces them to change it on next login)
app.post('/api/admin/users/:id/reset-password', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const id = parseInt(req.params.id, 10);
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  try {
    const r = await pool.query('SELECT username FROM users WHERE id = $1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    await pool.query(
      'UPDATE users SET password_hash = $1, must_change_password = TRUE WHERE id = $2',
      [pwHash(newPassword), id]
    );
    logActivity('user-pwreset', `Reset password for ${r.rows[0].username}`, null, 'admin');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete a user
app.delete('/api/admin/users/:id', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const id = parseInt(req.params.id, 10);
  if (req.user && req.user.id === id) {
    return res.status(400).json({ error: 'You cannot delete yourself' });
  }
  try {
    const r = await pool.query('SELECT username FROM users WHERE id = $1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    logActivity('user-delete', `Deleted user: ${r.rows[0].username}`, null, 'admin');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Toggle the legacy shared-password mode on/off
app.post('/api/admin/legacy-mode', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  const { enabled } = req.body || {};
  ALLOW_LEGACY_PASSWORD = !!enabled;
  logActivity('legacy-mode', `Legacy shared password ${enabled ? 'ENABLED' : 'DISABLED'}`, null, 'admin');
  res.json({ ok: true, allowLegacyPassword: ALLOW_LEGACY_PASSWORD });
});
app.get('/api/admin/legacy-mode', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  res.json({ allowLegacyPassword: ALLOW_LEGACY_PASSWORD });
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

// Get activity log (admin only). Optional ?user=Lee Lockwood to filter by user.
app.get('/api/admin/log', async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'Admin only' });
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 300, 1000);
    const filter = (req.query.user || '').trim();
    let result;
    if (filter) {
      result = await pool.query(
        'SELECT * FROM activity_log WHERE LOWER(user_name) LIKE $1 ORDER BY ts DESC LIMIT $2',
        ['%' + filter.toLowerCase() + '%', limit]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM activity_log ORDER BY ts DESC LIMIT $1',
        [limit]
      );
    }
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

// Rate-limit shift-save logging so the activity log isn't flooded by autosaves.
// Only log a save once per minute per (user, shift).
const shiftSaveLastLog = new Map(); // key: userId+shiftKey -> timestamp
app.put('/api/shifts/:key', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO shifts (key, data, updated_at) VALUES ($1, $2, NOW())
      ON CONFLICT (key) DO UPDATE SET data = $2, updated_at = NOW()
    `, [req.params.key, req.body]);
    io.emit('shift-updated', { key: req.params.key });
    // Rate-limited audit log entry: who saved which shift and when
    const userKey = (req.user?.id || 'anon') + ':' + req.params.key;
    const now = Date.now();
    const last = shiftSaveLastLog.get(userKey) || 0;
    if (now - last > 60000) {
      shiftSaveLastLog.set(userKey, now);
      logFromReq(req, 'shift-save', 'Saved shift data', req.params.key);
    }
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
