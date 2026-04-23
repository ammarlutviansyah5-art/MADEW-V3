# Madew Burgers — Node.js Auth + OTP + SQLite

## Apa yang sudah disiapkan
- Sign in pakai email + password
- Sign up pakai email + OTP
- Lupa password pakai OTP
- Profil tersimpan di database: nama, bio, avatar
- Riwayat pesanan tersimpan di database
- Cookie auth httpOnly

## File penting
- `server.js` — backend Express + SQLite
- `public/index.html` — versi HTML yang sudah dipatch
- `public/auth-client.js` — logic frontend untuk auth dan sync profile/order
- `.env.example` — contoh konfigurasi

## Cara pakai
1. Install dependency:
   ```bash
   npm install
   ```
2. Copy `.env.example` ke `.env`, lalu isi SMTP.
3. Jalankan server:
   ```bash
   npm start
   ```
4. Buka `http://localhost:3000`

## Catatan integrasi ke file lama
Kalau kamu mau tetap pakai file HTML asli yang kamu upload, ambil:
- blok modal `auth-modal` dari `public/index.html`
- tag `<script src="/auth-client.js"></script>`

Kalau backend jalan, fitur login lama yang masih gimmick sudah bisa diganti penuh.
