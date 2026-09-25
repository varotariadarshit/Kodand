const Database = require('better-sqlite3');
const db = new Database('./notes.db');
db.exec(`CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL)`);

const ID_PATTERN = /^note-(\d+)$/;
function parseId(value) {
  const match = ID_PATTERN.exec(value);
  return match ? Number(match[1]) : null;
}

function addNote(body) {
  return db.prepare('INSERT INTO notes (body) VALUES (?)').run(body);
}

module.exports = { parseId, addNote };
