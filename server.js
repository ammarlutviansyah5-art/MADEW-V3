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

const app = express();
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

initDb();

const smtpTransport = createTransport();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.post('/api/auth/register', async (req, res) => {
  try {

    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Nama, email, dan password wajib diisi.' });
    }

    const cleanEmail = String(email).toLowerCase().trim();
    const passwordHash = await bcrypt.hash(password, 10);

    const existing = db.prepare('SELECT * FROM users WHERE email=?').get(cleanEmail);

    let userId;

    if (existing) {

      db.prepare(`
      UPDATE users SET name=?, password_hash=?, verified_at=NULL
      WHERE id=?`).run(name, passwordHash, existing.id);

      userId = existing.id;

    } else {

      const result = db.prepare(`
      INSERT INTO users (name,email,password_hash)
      VALUES (?,?,?)`).run(name, cleanEmail, passwordHash);

      userId = result.lastInsertRowid;

    }

    const otp = issueOtp(userId, cleanEmail, 'register');

    await sendOtpEmail(
      cleanEmail,
      "Verifikasi akun Madew Burger's",
      otp,
      "register"
    );

    res.json({
      message: 'Akun dibuat, OTP dikirim ke email.',
      needsVerification: true
    });

  } catch (err) {

    console.error(err);
    res.status(500).json({ message: 'Gagal membuat akun.' });

  }
});

app.post('/api/auth/verify-register', (req, res) => {

  const { email, otp } = req.body || {};
  const cleanEmail = String(email || '').toLowerCase().trim();

  const user = db.prepare(
    'SELECT * FROM users WHERE email=?'
  ).get(cleanEmail);

  if (!user) {
    return res.status(404).json({ message: 'Akun tidak ditemukan.' });
  }

  const valid = verifyOtp(cleanEmail, otp, 'register');

  if (!valid) {
    return res.status(400).json({ message: 'OTP salah atau kadaluarsa.' });
  }

  db.prepare(`
  UPDATE users SET verified_at=CURRENT_TIMESTAMP
  WHERE id=?`).run(user.id);

  setAuthCookie(res, user);

  res.json({ message: 'Akun berhasil diverifikasi.' });

});

app.listen(PORT, () => {
  console.log("Server berjalan di http://localhost:" + PORT);
});

function initDb() {

  db.exec(`

CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
email TEXT UNIQUE,
password_hash TEXT,
verified_at TEXT
);

CREATE TABLE IF NOT EXISTS otp_tokens(
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
email TEXT,
purpose TEXT,
otp_hash TEXT,
expires_at INTEGER,
used_at INTEGER
);

`);

}

function issueOtp(userId, email, purpose) {

  const otp = String(Math.floor(100000 + Math.random() * 900000));

  const hash = crypto
    .createHash('sha256')
    .update(otp)
    .digest('hex');

  const expires = Date.now() + 10 * 60 * 1000;

  db.prepare(`
INSERT INTO otp_tokens
(user_id,email,purpose,otp_hash,expires_at)
VALUES(?,?,?,?,?)
`).run(userId, email, purpose, hash, expires);

  return otp;

}

function verifyOtp(email, otp, purpose) {

  const hash = crypto
    .createHash('sha256')
    .update(String(otp))
    .digest('hex');

  const row = db.prepare(`
SELECT * FROM otp_tokens
WHERE email=? AND purpose=?
ORDER BY id DESC LIMIT 1
`).get(email, purpose);

  if (!row) return false;

  if (Date.now() > row.expires_at) return false;

  if (row.otp_hash !== hash) return false;

  return true;

}

function createTransport() {

  if (!process.env.SMTP_HOST) {
    console.log("SMTP tidak diset, OTP akan muncul di console");
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
    console.log("OTP:", otp);
    return;
  }

  await smtpTransport.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    html: `<h2>Madew Burger's</h2>
    <p>Kode OTP kamu:</p>
    <h1>${otp}</h1>
    <p>Berlaku 10 menit</p>`
  });

}

function setAuthCookie(res, user) {

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax'
  });

}
