const express = require('express');
const path = require('path');
const fs = require('fs');
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
app.use(express.json({ limit: '4mb' }));
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
    const cleanName = String(name || '').trim();
    const cleanEmail = normalizeEmail(email);
    const cleanPassword = String(password || '');

    if (!cleanName || !cleanEmail || !cleanPassword) {
      return res.status(400).json({ message: 'Nama, email, dan password wajib diisi.' });
    }
    if (cleanPassword.length < 8) {
      return res.status(400).json({ message: 'Password minimal 8 karakter.' });
    }

    const existing = getUserByEmail(cleanEmail);
    const passwordHash = await bcrypt.hash(cleanPassword, 10);

    let user;
    if (existing) {
      db.prepare(`
        UPDATE users
        SET name = ?, password_hash = ?, verified_at = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(cleanName, passwordHash, existing.id);
      user = getUserByEmail(cleanEmail);
    } else {
      const result = db.prepare(`
        INSERT INTO users (name, email, password_hash, bio, avatar_url, verified_at)
        VALUES (?, ?, ?, '', '', NULL)
      `).run(cleanName, cleanEmail, passwordHash);
      user = getUserById(result.lastInsertRowid);
    }

    const otp = issueOtp(user.id, cleanEmail, 'register');
    await sendOtpEmail(cleanEmail, 'Verifikasi akun Madew Burger\'s', otp, 'register');

    return res.json({
      message: 'Akun dibuat. OTP verifikasi sudah dikirim ke email.',
      needsVerification: true
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal membuat akun.' });
  }
});

app.post('/api/auth/verify-register', async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    const cleanOtp = String(otp || '').trim();

    if (!cleanEmail || !cleanOtp) {
      return res.status(400).json({ message: 'Email dan OTP wajib diisi.' });
    }

    const user = getUserByEmail(cleanEmail);
    if (!user) return res.status(404).json({ message: 'Akun tidak ditemukan.' });

    const otpRecord = verifyOtp(cleanEmail, cleanOtp, 'register');
    if (!otpRecord) return res.status(400).json({ message: 'OTP tidak valid atau sudah kadaluarsa.' });

    db.prepare(`
      UPDATE users
      SET verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    const updated = getUserById(user.id);
    setAuthCookie(res, updated);
    return res.json({
      message: 'Akun berhasil diverifikasi.',
      user: sanitizeUser(updated)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal verifikasi akun.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    const cleanPassword = String(password || '');

    if (!cleanEmail || !cleanPassword) {
      return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }

    const user = getUserByEmail(cleanEmail);
    if (!user) return res.status(400).json({ message: 'Email atau password salah.' });
    if (!user.verified_at) return res.status(403).json({ message: 'Akun belum diverifikasi. Cek OTP di email.' });

    const ok = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!ok) return res.status(400).json({ message: 'Email atau password salah.' });

    setAuthCookie(res, user);
    return res.json({
      message: 'Login berhasil.',
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal login.' });
  }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail) return res.status(400).json({ message: 'Email wajib diisi.' });

    const user = getUserByEmail(cleanEmail);
    if (!user) {
      return res.json({ message: 'Kalau email terdaftar, OTP reset sudah dikirim.' });
    }

    const otp = issueOtp(user.id, cleanEmail, 'reset');
    await sendOtpEmail(cleanEmail, 'Reset password Madew Burger\'s', otp, 'reset');
    return res.json({ message: 'OTP reset sudah dikirim ke email kamu.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal mengirim OTP reset.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, password } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    const cleanOtp = String(otp || '').trim();
    const cleanPassword = String(password || '');

    if (!cleanEmail || !cleanOtp || !cleanPassword) {
      return res.status(400).json({ message: 'Email, OTP, dan password baru wajib diisi.' });
    }
    if (cleanPassword.length < 8) {
      return res.status(400).json({ message: 'Password minimal 8 karakter.' });
    }

    const user = getUserByEmail(cleanEmail);
    if (!user) return res.status(404).json({ message: 'Akun tidak ditemukan.' });

    const otpRecord = verifyOtp(cleanEmail, cleanOtp, 'reset');
    if (!otpRecord) return res.status(400).json({ message: 'OTP reset tidak valid atau sudah kadaluarsa.' });

    const passwordHash = await bcrypt.hash(cleanPassword, 10);
    db.prepare(`
      UPDATE users
      SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(passwordHash, user.id);

    return res.json({ message: 'Password berhasil diganti.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal mengganti password.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, cookieOptions());
  res.json({ message: 'Logout berhasil.' });
});

app.get('/api/me', authRequired, (req, res) => {
  const user = getUserById(req.user.id);
  if (!user) return res.status(404).json({ message: 'Akun tidak ditemukan.' });
  return res.json({ user: sanitizeUser(user) });
});

app.put('/api/me/profile', authRequired, (req, res) => {
  const { name, bio, avatar_url } = req.body || {};
  const cleanName = String(name || '').trim();
  const cleanBio = String(bio || '').trim();
  const cleanAvatar = String(avatar_url || '').trim();

  if (!cleanName) return res.status(400).json({ message: 'Nama tidak boleh kosong.' });

  db.prepare(`
    UPDATE users
    SET name = ?, bio = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(cleanName, cleanBio, cleanAvatar, req.user.id);

  const user = getUserById(req.user.id);
  return res.json({ message: 'Profil tersimpan.', user: sanitizeUser(user) });
});

app.get('/api/me/orders', authRequired, (req, res) => {
  const orders = getOrdersForUser(req.user.id);
  return res.json({ orders });
});

app.post('/api/orders', authRequired, (req, res) => {
  try {
    const order = normalizeOrderInput(req.body || {}, req.user.id);
    const stmt = db.prepare(`
      INSERT INTO orders (
        id, user_id, items_json, item_label, qty, payment_method, promo_code, discount_amount,
        shipping_voucher, shipping_base, shipping_discount, shipping_final, proof_json, total,
        time_label, status, driver_name, driver_vehicle, driver_plate, gps_label, location_name,
        location, review_json, support_locked, support_outcome, support_started_at, support_resolved_at,
        created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
      )
    `);
    stmt.run(
      order.id,
      req.user.id,
      JSON.stringify(order.items || []),
      order.itemLabel,
      order.qty,
      order.paymentMethod,
      order.promoCode,
      order.discountAmount,
      order.shippingVoucher,
      order.shippingBase,
      order.shippingDiscount,
      order.shippingFinal,
      JSON.stringify(order.proof || null),
      order.total,
      order.time,
      order.status,
      order.driverName,
      order.driverVehicle,
      order.driverPlate,
      order.gpsLabel,
      order.locationName,
      order.location,
      JSON.stringify(order.review || null),
      order.supportLocked ? 1 : 0,
      order.supportOutcome || null,
      order.supportStartedAt || null,
      order.supportResolvedAt || null
    );
    return res.json({ message: 'Order tersimpan.', order });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Gagal menyimpan order.' });
  }
});

app.patch('/api/orders/:id', authRequired, (req, res) => {
  const orderId = Number(req.params.id);
  const existing = getOrderById(orderId, req.user.id);
  if (!existing) return res.status(404).json({ message: 'Order tidak ditemukan.' });

  const payload = req.body || {};
  const next = { ...existing };

  if (payload.review) next.review = payload.review;
  if (typeof payload.supportLocked !== 'undefined') next.supportLocked = !!payload.supportLocked;
  if (typeof payload.supportOutcome !== 'undefined') next.supportOutcome = payload.supportOutcome;
  if (typeof payload.supportStartedAt !== 'undefined') next.supportStartedAt = payload.supportStartedAt;
  if (typeof payload.supportResolvedAt !== 'undefined') next.supportResolvedAt = payload.supportResolvedAt;

  db.prepare(`
    UPDATE orders
    SET review_json = ?, support_locked = ?, support_outcome = ?, support_started_at = ?, support_resolved_at = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND user_id = ?
  `).run(
    JSON.stringify(next.review || null),
    next.supportLocked ? 1 : 0,
    next.supportOutcome || null,
    next.supportStartedAt || null,
    next.supportResolvedAt || null,
    orderId,
    req.user.id
  );

  return res.json({ message: 'Order diperbarui.', order: next });
});

app.delete('/api/orders/:id', authRequired, (req, res) => {
  const orderId = Number(req.params.id);
  db.prepare('DELETE FROM orders WHERE id = ? AND user_id = ?').run(orderId, req.user.id);
  return res.json({ message: 'Order dihapus.' });
});

app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint tidak ditemukan.' });
});

app.listen(PORT, () => {
  console.log(`Madew auth server running on http://localhost:${PORT}`);
});

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT NOT NULL DEFAULT '',
      avatar_url TEXT NOT NULL DEFAULT '',
      verified_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS otp_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL,
      items_json TEXT NOT NULL,
      item_label TEXT NOT NULL,
      qty INTEGER NOT NULL,
      payment_method TEXT NOT NULL,
      promo_code TEXT,
      discount_amount INTEGER NOT NULL DEFAULT 0,
      shipping_voucher TEXT,
      shipping_base INTEGER NOT NULL DEFAULT 0,
      shipping_discount INTEGER NOT NULL DEFAULT 0,
      shipping_final INTEGER NOT NULL DEFAULT 0,
      proof_json TEXT,
      total INTEGER NOT NULL DEFAULT 0,
      time_label TEXT NOT NULL,
      status TEXT NOT NULL,
      driver_name TEXT NOT NULL,
      driver_vehicle TEXT NOT NULL,
      driver_plate TEXT NOT NULL,
      gps_label TEXT NOT NULL,
      location_name TEXT NOT NULL,
      location TEXT NOT NULL,
      review_json TEXT,
      support_locked INTEGER NOT NULL DEFAULT 0,
      support_outcome TEXT,
      support_started_at TEXT,
      support_resolved_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}

function createTransport() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('SMTP env not configured. OTP emails will be logged to console.');
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    bio: user.bio || '',
    avatar_url: user.avatar_url || '',
    verified_at: user.verified_at || null,
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}

function issueOtp(userId, email, purpose) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
  const expiresAt = Date.now() + 10 * 60 * 1000;

  db.prepare(`
    INSERT INTO otp_tokens (user_id, email, purpose, otp_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId || null, email, purpose, otpHash, expiresAt);

  return otp;
}

function verifyOtp(email, otp, purpose) {
  const otpHash = crypto.createHash('sha256').update(String(otp || '').trim()).digest('hex');
  const row = db.prepare(`
    SELECT * FROM otp_tokens
    WHERE email = ? AND purpose = ? AND used_at IS NULL
    ORDER BY id DESC
    LIMIT 1
  `).get(email, purpose);

  if (!row) return null;
  if (Date.now() > row.expires_at) return null;
  if (row.otp_hash !== otpHash) return null;

  db.prepare('UPDATE otp_tokens SET used_at = strftime(\'%s\',\'now\') WHERE id = ?').run(row.id);
  return row;
}

async function sendOtpEmail(to, subject, otp, purpose) {
  const purposeLabel = purpose === 'reset' ? 'reset password' : 'verifikasi akun';
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111">
      <h2 style="margin:0 0 12px">Madew Burger's</h2>
      <p>OTP untuk ${purposeLabel} kamu:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:6px;margin:18px 0">${otp}</div>
      <p>Kode ini berlaku 10 menit.</p>
    </div>
  `;

  if (!smtpTransport) {
    console.log(`OTP ${purpose} for ${to}: ${otp}`);
    return;
  }

  await smtpTransport.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    html
  });
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: String(process.env.COOKIE_SECURE || 'false') === 'true',
    maxAge: 7 * 24 * 60 * 60 * 1000
  };
}

function setAuthCookie(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  res.cookie(COOKIE_NAME, token, cookieOptions());
}

function authRequired(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id, email: decoded.email };
    return next();
  } catch {
    return res.status(401).json({ message: 'Unauthorized' });
  }
}

function getOrdersForUser(userId) {
  const rows = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(userId);
  return rows.map(decodeOrderRow);
}

function getOrderById(id, userId) {
  const row = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(id, userId);
  return decodeOrderRow(row);
}

function decodeOrderRow(row) {
  if (!row) return null;
  let items = [];
  let proof = null;
  let review = null;
  try { items = JSON.parse(row.items_json || '[]'); } catch {}
  try { proof = JSON.parse(row.proof_json || 'null'); } catch {}
  try { review = JSON.parse(row.review_json || 'null'); } catch {}
  return {
    id: row.id,
    items,
    itemLabel: row.item_label,
    qty: row.qty,
    paymentMethod: row.payment_method,
    promoCode: row.promo_code || '',
    discountAmount: row.discount_amount || 0,
    shippingVoucher: row.shipping_voucher || '',
    shippingBase: row.shipping_base || 0,
    shippingDiscount: row.shipping_discount || 0,
    shippingFinal: row.shipping_final || 0,
    proof,
    total: row.total || 0,
    time: row.time_label,
    status: row.status,
    driverName: row.driver_name,
    driverVehicle: row.driver_vehicle,
    driverPlate: row.driver_plate,
    gpsLabel: row.gps_label,
    locationName: row.location_name,
    location: row.location,
    review,
    supportLocked: !!row.support_locked,
    supportOutcome: row.support_outcome || null,
    supportStartedAt: row.support_started_at || null,
    supportResolvedAt: row.support_resolved_at || null
  };
}

function normalizeOrderInput(input, userId) {
  const items = Array.isArray(input.items) ? input.items : [];
  const order = {
    id: Number(input.id || Date.now()),
    userId,
    items,
    itemLabel: String(input.itemLabel || items.map((i) => i.name).join(', ')),
    qty: Number(input.qty || items.reduce((sum, item) => sum + Number(item.qty || 0), 0)),
    paymentMethod: String(input.paymentMethod || 'Cash'),
    promoCode: String(input.promoCode || ''),
    discountAmount: Number(input.discountAmount || 0),
    shippingVoucher: String(input.shippingVoucher || ''),
    shippingBase: Number(input.shippingBase || 0),
    shippingDiscount: Number(input.shippingDiscount || 0),
    shippingFinal: Number(input.shippingFinal || 0),
    proof: input.proof || null,
    total: Number(input.total || 0),
    time: String(input.time || new Date().toLocaleString('id-ID')),
    status: String(input.status || 'Selesai Diantarkan'),
    driverName: String(input.driverName || ''),
    driverVehicle: String(input.driverVehicle || ''),
    driverPlate: String(input.driverPlate || ''),
    gpsLabel: String(input.gpsLabel || ''),
    locationName: String(input.locationName || ''),
    location: String(input.location || ''),
    review: input.review || null,
    supportLocked: !!input.supportLocked,
    supportOutcome: input.supportOutcome || null,
    supportStartedAt: input.supportStartedAt || null,
    supportResolvedAt: input.supportResolvedAt || null
  };

  return order;
}
