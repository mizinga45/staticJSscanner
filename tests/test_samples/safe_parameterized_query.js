// Test: Safe code - parameterized query (NO vulnerabilities expected)
// Expected: NOT DETECTED
const db = require('better-sqlite3')('database.db');

function getUser(userId) {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(userId);
}

function sanitizedOutput(text) {
    const el = document.getElementById('output');
    el.textContent = text; // safe - uses textContent not innerHTML
}

const apiKey = process.env.API_KEY; // safe - loaded from environment
