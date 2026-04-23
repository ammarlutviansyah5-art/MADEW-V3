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
const OTP_TTL_MS = Number(process.env.OTP_TTL_MS || 10 * 60 * 1000);
const JSON_LIMIT = process.env.JSON_LIMIT || '10mb';

const app = express();
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
initializeDatabase();

const mailer = createMailerFromEnv();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: JSON_LIMIT }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/api/health', (_req, res) => {
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
    if (!cleanName || !cleanEmail || !String(password).trim()) {
      return res.status(400).json({ message: 'Nama, email, dan password wajib diisi.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);

    let userId;
    if (existing) {
      db.prepare(`
        UPDATE users
        SET name = ?, password_hash = ?, verified_at = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(cleanName, passwordHash, existing.id);
      userId = existing.id;
    } else {
      const result = db.prepare(`
        INSERT INTO users (name, email, password_hash, bio, avatar_url)
        VALUES (?, ?, ?, '', '')
      `).run(cleanName, cleanEmail, passwordHash);
      userId = Number(result.lastInsertRowid);
    }

    const otp = issueOtp(userId, cleanEmail, 'register');
    const mailResult = await sendOtpEmail(cleanEmail, "Verifikasi akun Madew Burger's", otp, 'register');

    return res.status(201).json({
      message: mailResult.delivered
        ? 'Akun dibuat, OTP dikirim ke email.'
        : 'Akun dibuat, OTP belum bisa dikirim otomatis. Cek log server untuk OTP.',
      needsVerification: true,
      emailSent: mailResult.delivered,
    });
  } catch (err) {
    console.error('Register error:', err);
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

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const otpRow = verifyOtp(cleanEmail, otp, 'register');
    if (!otpRow) {
      return res.status(400).json({ message: 'OTP salah atau kadaluarsa.' });
    }

    db.prepare('UPDATE otp_tokens SET used_at = ? WHERE id = ?').run(Date.now(), otpRow.id);
    db.prepare(`
      UPDATE users
      SET verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(user.id);

    const verifiedUser = getUserById(user.id);
    setAuthCookie(res, verifiedUser);

    return res.json({
      message: 'Akun berhasil diverifikasi.',
      user: publicUser(verifiedUser),
    });
  } catch (err) {
    console.error('Verify register error:', err);
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

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (!user) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    const ok = await bcrypt.compare(String(password), user.password_hash || '');
    if (!ok) {
      return res.status(401).json({ message: 'Email atau password salah.' });
    }

    if (!user.verified_at) {
      return res.status(403).json({ message: 'Akun belum diverifikasi. Silakan cek OTP.' });
    }

    setAuthCookie(res, user);
    return res.json({ message: 'Login berhasil.', user: publicUser(user) });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Login gagal.' });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, cookieOptions());
  res.json({ message: 'Logout berhasil.' });
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail) {
      return res.status(400).json({ message: 'Email wajib diisi.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const purpose = user.verified_at ? 'reset_password' : 'register';
    const subject = purpose === 'register'
      ? "Verifikasi akun Madew Burger's"
      : 'OTP reset password Madew Burger\'s';
    const otp = issueOtp(user.id, cleanEmail, purpose);
    const mailResult = await sendOtpEmail(cleanEmail, subject, otp, purpose);

    return res.json({
      message: mailResult.delivered
        ? (purpose === 'register' ? 'OTP verifikasi sudah dikirim.' : 'OTP reset sudah dikirim.')
        : (purpose === 'register'
          ? 'OTP verifikasi dibuat, tapi email belum bisa dikirim otomatis. Cek log server.'
          : 'OTP reset dibuat, tapi email belum bisa dikirim otomatis. Cek log server.'),
      emailSent: mailResult.delivered,
      purpose,
    });
  } catch (err) {
    console.error('Request reset error:', err);
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

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ message: 'Akun tidak ditemukan.' });
    }

    const otpRow = verifyOtp(cleanEmail, otp, 'reset_password');
    if (!otpRow) {
      return res.status(400).json({ message: 'OTP salah atau kadaluarsa.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);
    db.prepare('UPDATE otp_tokens SET used_at = ? WHERE id = ?').run(Date.now(), otpRow.id);
    db.prepare(`
      UPDATE users
      SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(passwordHash, user.id);

    return res.json({ message: 'Password berhasil diganti.' });
  } catch (err) {
    console.error('Reset password error:', err);
    return res.status(500).json({ message: 'Reset password gagal.' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = getUserById(req.user.id);
  if (!user) {
    res.clearCookie(COOKIE_NAME, cookieOptions());
    return res.status(401).json({ message: 'Sesi tidak valid.' });
  }
  return res.json({ user: publicUser(user) });
});

app.get('/api/me/orders', requireAuth, (_req, res) => {
  try {
    const orders = db
      .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC, id DESC')
      .all(_req.user.id)
      .map(publicOrder);

    return res.json({ orders });
  } catch (err) {
    console.error('Fetch orders error:', err);
    return res.status(500).json({ message: 'Gagal mengambil riwayat pesanan.' });
  }
});

app.put('/api/me/profile', requireAuth, (req, res) => {
  try {
    const { name, bio = '', avatar_url = '' } = req.body || {};
    const cleanName = String(name || '').trim();
    if (!cleanName) {
      return res.status(400).json({ message: 'Nama profil tidak boleh kosong.' });
    }

    const bioText = String(bio || '').trim();
    const avatarText = String(avatar_url || '').trim();

    db.prepare(`
      UPDATE users
      SET name = ?, bio = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(cleanName, bioText, avatarText, req.user.id);

    const user = getUserById(req.user.id);
    return res.json({ message: 'Profil berhasil disimpan ke database.', user: publicUser(user) });
  } catch (err) {
    console.error('Update profile error:', err);
    return res.status(500).json({ message: 'Gagal menyimpan profil.' });
  }
});

app.post('/api/orders', requireAuth, (req, res) => {
  try {
    const order = normalizeOrderPayload(req.body || {}, req.user.id);
    const insert = db.prepare(`
      INSERT OR REPLACE INTO orders (
        id, user_id, items_json, item_label, qty, payment_method, promo_code,
        discount_amount, shipping_voucher, shipping_base, shipping_discount,
        shipping_final, proof_json, total, time_label, status, driver_name,
        driver_vehicle, driver_plate, gps_label, location_name, location,
        review_json, support_locked, support_outcome, support_started_at,
        support_resolved_at, created_at, updated_at
      ) VALUES (
        @id, @user_id, @items_json, @item_label, @qty, @payment_method, @promo_code,
        @discount_amount, @shipping_voucher, @shipping_base, @shipping_discount,
        @shipping_final, @proof_json, @total, @time_label, @status, @driver_name,
        @driver_vehicle, @driver_plate, @gps_label, @location_name, @location,
        @review_json, @support_locked, @support_outcome, @support_started_at,
        @support_resolved_at, COALESCE(@created_at, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
      )
    `);

    insert.run(order);
    const saved = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(order.id, req.user.id);
    return res.status(201).json({ message: 'Pesanan tersimpan.', order: publicOrder(saved) });
  } catch (err) {
    console.error('Create order error:', err);
    return res.status(500).json({ message: 'Gagal menyimpan pesanan.' });
  }
});

app.patch('/api/orders/:id', requireAuth, (req, res) => {
  try {
    const orderId = Number(req.params.id);
    if (!Number.isFinite(orderId)) {
      return res.status(400).json({ message: 'ID pesanan tidak valid.' });
    }

    const existing = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(orderId, req.user.id);
    if (!existing) {
      return res.status(404).json({ message: 'Pesanan tidak ditemukan.' });
    }

    const patch = req.body || {};
    const reviewJson = patch.review === undefined ? existing.review_json : JSON.stringify(patch.review);
    const status = patch.status === undefined ? existing.status : String(patch.status);
    const supportLocked = patch.supportLocked === undefined ? existing.support_locked : toInt(patch.supportLocked, existing.support_locked);
    const supportOutcome = patch.supportOutcome === undefined ? existing.support_outcome : String(patch.supportOutcome || '');

    db.prepare(`
      UPDATE orders
      SET review_json = ?, status = ?, support_locked = ?, support_outcome = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `).run(reviewJson, status, supportLocked, supportOutcome, orderId, req.user.id);

    const saved = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(orderId, req.user.id);
    return res.json({ message: 'Pesanan diperbarui.', order: publicOrder(saved) });
  } catch (err) {
    console.error('Patch order error:', err);
    return res.status(500).json({ message: 'Gagal memperbarui pesanan.' });
  }
});

app.delete('/api/orders/:id', requireAuth, (req, res) => {
  try {
    const orderId = Number(req.params.id);
    if (!Number.isFinite(orderId)) {
      return res.status(400).json({ message: 'ID pesanan tidak valid.' });
    }

    const info = db.prepare('DELETE FROM orders WHERE id = ? AND user_id = ?').run(orderId, req.user.id);
    if (!info.changes) {
      return res.status(404).json({ message: 'Pesanan tidak ditemukan.' });
    }

    return res.json({ message: 'Pesanan dihapus.' });
  } catch (err) {
    console.error('Delete order error:', err);
    return res.status(500).json({ message: 'Gagal menghapus pesanan.' });
  }
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  if (!res.headersSent) {
    res.status(500).json({ message: 'Terjadi kesalahan server.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});

function initializeDatabase() {
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

  ensureColumn('users', 'bio', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('users', 'avatar_url', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('users', 'created_at', "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
  ensureColumn('users', 'updated_at', "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");

  ensureColumn('otp_tokens', 'used_at', 'INTEGER');
  ensureColumn('otp_tokens', 'created_at', "INTEGER NOT NULL DEFAULT (strftime('%s','now'))");

  ensureIndex('users', 'idx_users_email', 'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
  ensureIndex('otp_tokens', 'idx_otp_lookup', 'CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_tokens(email, purpose, used_at, expires_at, id)');
  ensureIndex('orders', 'idx_orders_user', 'CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, id)');
}

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((col) => col.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function ensureIndex(_table, _name, sql) {
  db.exec(sql);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function toInt(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
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
    created_at: user.created_at || null,
    updated_at: user.updated_at || null,
  };
}

function publicOrder(order) {
  if (!order) return null;
  return {
    id: order.id,
    user_id: order.user_id,
    items: safeParse(order.items_json, []),
    itemLabel: order.item_label || '',
    qty: order.qty || 0,
    paymentMethod: order.payment_method || '',
    promoCode: order.promo_code || '',
    discountAmount: order.discount_amount || 0,
    shippingVoucher: order.shipping_voucher || '',
    shippingBase: order.shipping_base || 0,
    shippingDiscount: order.shipping_discount || 0,
    shippingFinal: order.shipping_final || 0,
    proof: safeParse(order.proof_json, null),
    total: order.total || 0,
    time: order.time_label || '',
    status: order.status || '',
    driverName: order.driver_name || '',
    driverVehicle: order.driver_vehicle || '',
    driverPlate: order.driver_plate || '',
    gpsLabel: order.gps_label || '',
    locationName: order.location_name || '',
    location: order.location || '',
    review: safeParse(order.review_json, null),
    supportLocked: Boolean(order.support_locked),
    supportOutcome: order.support_outcome || '',
    supportStartedAt: order.support_started_at || null,
    supportResolvedAt: order.support_resolved_at || null,
    created_at: order.created_at || null,
    updated_at: order.updated_at || null,
  };
}

function safeParse(value, fallback) {
  if (value === null || value === undefined || value === '') return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function issueOtp(userId, email, purpose) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  const expires = Date.now() + OTP_TTL_MS;

  db.prepare(`
    INSERT INTO otp_tokens (user_id, email, purpose, otp_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, email, purpose, hash, expires);

  return otp;
}

function verifyOtp(email, otp, purpose) {
  const hash = crypto.createHash('sha256').update(String(otp)).digest('hex');
  const row = db.prepare(`
    SELECT * FROM otp_tokens
    WHERE email = ?
      AND purpose = ?
      AND used_at IS NULL
    ORDER BY id DESC
    LIMIT 1
  `).get(email, purpose);

  if (!row) return null;
  if (Date.now() > Number(row.expires_at || 0)) return null;
  if (row.otp_hash !== hash) return null;
  return row;
}

function createMailerFromEnv() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log('SMTP belum diset, OTP akan dicetak ke console server.');
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendOtpEmail(to, subject, otp, purpose) {
  if (!mailer) {
    console.log(`[OTP:${purpose}] ${to} => ${otp}`);
    return { delivered: false, reason: 'smtp-not-configured' };
  }

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  try {
    await mailer.sendMail({
      from,
      to,
      subject,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6">
          <h2>Madew Burger's</h2>
          <p>Kode OTP kamu:</p>
          <div style="font-size: 28px; font-weight: 700; letter-spacing: 4px">${otp}</div>
          <p>Berlaku 10 menit.</p>
        </div>
      `,
    });
    return { delivered: true };
  } catch (error) {
    console.error('Gagal kirim email OTP:', error);
    console.log(`[OTP:${purpose}] ${to} => ${otp}`);
    return { delivered: false, reason: 'smtp-send-failed' };
  }
}

function setAuthCookie(res, user) {
  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.cookie(COOKIE_NAME, token, cookieOptions());
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: String(process.env.COOKIE_SECURE || 'false') === 'true',
    path: '/',
  };
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ message: 'Belum login.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    res.clearCookie(COOKIE_NAME, cookieOptions());
    return res.status(401).json({ message: 'Sesi login sudah habis.' });
  }
}

function normalizeOrderPayload(body, userId) {
  const id = Number.isFinite(Number(body.id)) ? Number(body.id) : Date.now();
  return {
    id,
    user_id: userId,
    items_json: JSON.stringify(body.items ?? []),
    item_label: String(body.itemLabel ?? body.item_label ?? ''),
    qty: toInt(body.qty, 0),
    payment_method: String(body.paymentMethod ?? body.payment_method ?? ''),
    promo_code: body.promoCode ?? body.promo_code ?? '',
    discount_amount: toInt(body.discountAmount ?? body.discount_amount, 0),
    shipping_voucher: body.shippingVoucher ?? body.shipping_voucher ?? '',
    shipping_base: toInt(body.shippingBase ?? body.shipping_base, 0),
    shipping_discount: toInt(body.shippingDiscount ?? body.shipping_discount, 0),
    shipping_final: toInt(body.shippingFinal ?? body.shipping_final, 0),
    proof_json: body.proof === undefined ? null : JSON.stringify(body.proof),
    total: toInt(body.total, 0),
    time_label: String(body.time ?? body.time_label ?? ''),
    status: String(body.status ?? 'Selesai Diantarkan'),
    driver_name: String(body.driverName ?? body.driver_name ?? ''),
    driver_vehicle: String(body.driverVehicle ?? body.driver_vehicle ?? ''),
    driver_plate: String(body.driverPlate ?? body.driver_plate ?? ''),
    gps_label: String(body.gpsLabel ?? body.gps_label ?? ''),
    location_name: String(body.locationName ?? body.location_name ?? ''),
    location: String(body.location ?? ''),
    review_json: body.review === undefined ? null : JSON.stringify(body.review),
    support_locked: toInt(body.supportLocked ?? body.support_locked, 0),
    support_outcome: body.supportOutcome ?? body.support_outcome ?? null,
    support_started_at: body.supportStartedAt ?? body.support_started_at ?? null,
    support_resolved_at: body.supportResolvedAt ?? body.support_resolved_at ?? null,
    created_at: body.created_at ?? null,
  };
}
