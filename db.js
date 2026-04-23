const Database = require('better-sqlite3');
const path = require('path');

function openDatabase(dbPath = path.join(__dirname, 'madew.sqlite')) {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  return db;
}

module.exports = { openDatabase };
