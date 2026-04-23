const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
require('dotenv').config();

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DB_PATH = process.env.DB_PATH || path.join(ROOT, 'madew.sqlite');
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'madew_token';
const PORT = Number(process.env.PORT || 3000);
const EXPOSE_OTP = String(process.env.EXPOSE_OTP || '').toLowerCase() === '1';

const app = express();
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
initDb();

const smtpTransport = createTransport();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Nama, email, dan password wajib diisi.' });
    }

    const cleanName = String(name).trim();
    const cleanEmail = normalizeEmail(email);
    const cleanPassword = String(password);

    if (!cleanEmail || !cleanName || cleanPassword.length < 6) {
      return res.status(400).json({ message: 'Data akun tidak valid.' });
    }

    const passwordHash = await bcrypt.hash(cleanPassword, 10);
    const existing = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);

    let userId;
    if (existing) {
      db.prepare(`
        UPDATE users
        SET name=?, password_hash=?, verified_at=NULL
        WHERE id=?
      `).run(cleanName, passwordHash, existing.id);
      userId = existing.id;
    } else {
      const result = db.prepare(`
        INSERT INTO users (name, email, password_hash)
        VALUES (?, ?, ?)
      `).run(cleanName, cleanEmail, passwordHash);
      userId = Number(result.lastInsertRowid);
    }

    const otp = issueOtp(userId, cleanEmail, 'register');
    const emailResult = await sendOtpEmail(cleanEmail, "Verifikasi akun Madew Burger's", otp);

    const payload = {
      message: 'Akun dibuat, OTP dikirim ke email.',
      needsVerification: true
    };

    if (!emailResult.sent && EXPOSE_OTP) {
      payload.otp = otp;
      payload.debug = 'OTP ditampilkan karena SMTP belum aktif.';
    }

    return res.json(payload);
  } catch (err) {
    console.error('register error:', err);
    return res.status(500).json({ message: 'Gagal membuat akun.' });
  }
});

app.post('/api/auth/verify-register', (req, res) => {
  try {
    const { email, otp } = req.body || {};
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !otp) {
      return res.status(400).json({ message: 'Email dan OTP wajib diisi.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const valid = verifyOtp(cleanEmail, otp, 'register');
    if (!valid) {
      return res.status(400).json({ message: 'OTP salah atau kadaluarsa.' });
    }

    db.prepare(`
      UPDATE users
      SET verified_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).run(user.id);

    const updated = getUserById(user.id);
    setAuthCookie(res, updated);

    return res.json({
      message: 'Akun berhasil diverifikasi.',
      user: publicUser(updated)
    });
  } catch (err) {
    console.error('verify-register error:', err);
    return res.status(500).json({ message: 'Gagal verifikasi akun.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !password) {
      return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);
    if (!user) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    if (!user.verified_at) {
      return res.status(403).json({ message: 'Akun belum diverifikasi.' });
    }

    setAuthCookie(res, user);
    return res.json({ message: 'Login berhasil.', user: publicUser(user) });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ message: 'Login gagal.' });
  }
});

app.post('/api/auth/request-password-reset', (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail) {
      return res.status(400).json({ message: 'Email wajib diisi.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const otp = issueOtp(user.id, cleanEmail, 'reset-password');
    sendOtpEmail(cleanEmail, 'Reset password Madew Burger\'s', otp).catch((err) => {
      console.error('reset otp email error:', err);
    });

    const payload = { message: 'OTP reset sudah dikirim.' };
    if (EXPOSE_OTP && !smtpTransport) payload.otp = otp;
    return res.json(payload);
  } catch (err) {
    console.error('request reset error:', err);
    return res.status(500).json({ message: 'Gagal kirim OTP reset.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, password } = req.body || {};
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !otp || !password) {
      return res.status(400).json({ message: 'Email, OTP, dan password baru wajib diisi.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const valid = verifyOtp(cleanEmail, otp, 'reset-password');
    if (!valid) {
      return res.status(400).json({ message: 'OTP salah atau kadaluarsa.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    db.prepare(`UPDATE users SET password_hash=? WHERE id=?`).run(passwordHash, user.id);
    markOtpUsed(cleanEmail, 'reset-password');

    return res.json({ message: 'Password berhasil diganti.' });
  } catch (err) {
    console.error('reset-password error:', err);
    return res.status(500).json({ message: 'Reset password gagal.' });
  }
});

app.get('/api/me', (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ message: 'Belum login.' });
  }
  return res.json({ user: publicUser(user) });
});

app.get('/api/me/orders', (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ message: 'Belum login.' });
  }
  return res.json({ orders: [] });
});

app.put('/api/me/profile', (req, res) => {
  try {
    const user = getUserFromRequest(req);
    if (!user) {
      return res.status(401).json({ message: 'Belum login.' });
    }

    const { name, bio = '', avatar_url = '' } = req.body || {};
    const cleanName = String(name || '').trim();

    if (!cleanName) {
      return res.status(400).json({ message: 'Nama profil tidak boleh kosong.' });
    }

    db.prepare(`
      UPDATE users
      SET name=?, bio=?, avatar_url=?
      WHERE id=?
    `).run(cleanName, String(bio), String(avatar_url), user.id);

    const updated = getUserById(user.id);
    return res.json({ user: publicUser(updated) });
  } catch (err) {
    console.error('profile error:', err);
    return res.status(500).json({ message: 'Gagal simpan profil.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ message: 'Logout berhasil.' });
});

app.use((req, res) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) {
    return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  }
  return res.status(404).json({ message: 'Route tidak ditemukan.' });
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      verified_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS otp_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  ensureColumn('users', 'bio', "TEXT DEFAULT ''");
  ensureColumn('users', 'avatar_url', "TEXT DEFAULT ''");
  ensureColumn('users', 'verified_at', 'TEXT');
  ensureColumn('users', 'created_at', 'TEXT DEFAULT CURRENT_TIMESTAMP');
  ensureColumn('otp_tokens', 'used_at', 'INTEGER');
  ensureColumn('otp_tokens', 'created_at', 'TEXT DEFAULT CURRENT_TIMESTAMP');
}

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((col) => col.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function normalizeEmail(email) {
  const value = String(email || '').trim().toLowerCase();
  return value || '';
}

function issueOtp(userId, email, purpose) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  const expires = Date.now() + 10 * 60 * 1000;

  db.prepare(`
    INSERT INTO otp_tokens (user_id, email, purpose, otp_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, email, purpose, hash, expires);

  return otp;
}

function verifyOtp(email, otp, purpose) {
  const hash = crypto.createHash('sha256').update(String(otp)).digest('hex');
  const row = db.prepare(`
    SELECT *
    FROM otp_tokens
    WHERE email=? AND purpose=? AND used_at IS NULL
    ORDER BY id DESC
    LIMIT 1
  `).get(email, purpose);

  if (!row) return false;
  if (Date.now() > row.expires_at) return false;
  if (row.otp_hash !== hash) return false;

  return true;
}

function markOtpUsed(email, purpose) {
  db.prepare(`
    UPDATE otp_tokens
    SET used_at=?
    WHERE email=? AND purpose=? AND used_at IS NULL
  `).run(Date.now(), email, purpose);
}

function createTransport() {
  if (!process.env.SMTP_HOST) {
    console.log('SMTP tidak diset, OTP akan muncul di console');
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendOtpEmail(to, subject, otp) {
  if (!smtpTransport) {
    console.log('OTP:', otp);
    return { sent: false };
  }

  try {
    await smtpTransport.sendMail({
      from: process.env.SMTP_FROM,
      to,
      subject,
      html: `<h2>Madew Burger's</h2><p>Kode OTP kamu:</p><h1>${otp}</h1><p>Berlaku 10 menit</p>`
    });
    return { sent: true };
  } catch (error) {
    console.error('sendOtpEmail failed:', error);
    console.log('OTP fallback:', otp);
    return { sent: false, error };
  }
}

function getUserFromRequest(req) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return null;

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload?.id) return null;
    return getUserById(payload.id);
  } catch {
    return null;
  }
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id=?').get(id) || null;
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    bio: user.bio || '',
    avatar_url: user.avatar_url || '',
    verified_at: user.verified_at || null,
    created_at: user.created_at || null
  };
}

function setAuthCookie(res, user) {
  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: String(process.env.COOKIE_SECURE || '').toLowerCase() === '1'
  });
}
