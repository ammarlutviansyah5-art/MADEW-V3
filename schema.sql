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
