// ─────────────────────────────────────────────────────────────────────────────
//  Inkwell  –  Server.js
//  node server.js
// ─────────────────────────────────────────────────────────────────────────────
const express = require('express');
const mysql   = require('mysql2');
const cors    = require('cors');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app    = express();
const PORT   = 3000;
const SECRET = 'inkwell_secret_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'No token' });
    jwt.verify(token, SECRET, (err, payload) => {
        if (err) return res.status(403).json({ message: 'Token invalid or expired' });
        req.userId = payload.userId;
        next();
    });
}

// ─── DB ───────────────────────────────────────────────────────────────────────
const db = mysql.createConnection({
    host:     'localhost',
    user:     'root',
    password: '',          // ← your MySQL password if any
    database: 'diary_app'
});

db.connect(err => {
    if (err) {
        console.error('\n❌  MySQL connection failed:', err.message);
        process.exit(1);
    }
    console.log('✅  MySQL connected');
    setupTables();
});

// ─── Table setup: create + migrate in one place ───────────────────────────────
function setupTables() {
    // Users table
    db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            name       VARCHAR(100)        NOT NULL,
            phone      VARCHAR(20)         NOT NULL,
            email      VARCHAR(100) UNIQUE NOT NULL,
            gender     VARCHAR(10)         NOT NULL,
            username   VARCHAR(50)  UNIQUE NOT NULL,
            password   VARCHAR(255)        NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `, err => {
        if (err) console.error('users table error:', err.message);
        else     console.log('✅  users table ready');
    });

    // diary_entries: create with bare minimum first
    db.query(`
        CREATE TABLE IF NOT EXISTS diary_entries (
            id      INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            content MEDIUMTEXT
        )
    `, err => {
        if (err) { console.error('diary_entries create error:', err.message); return; }
        console.log('✅  diary_entries table exists – running migrations…');
        runMigrations();
    });
}

// Runs ALTER TABLE only for columns/indexes that are missing.
// Works whether table is brand new or was created by old code.
function runMigrations() {

    // Check if a column exists in diary_entries
    function hasColumn(col, cb) {
        db.query(
            `SELECT COUNT(*) AS n FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='diary_entries' AND COLUMN_NAME=?`,
            [col], (err, rows) => cb(!err && rows[0].n > 0)
        );
    }

    // Check if an index exists in diary_entries
    function hasIndex(idx, cb) {
        db.query(
            `SELECT COUNT(*) AS n FROM information_schema.STATISTICS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='diary_entries' AND INDEX_NAME=?`,
            [idx], (err, rows) => cb(!err && rows[0].n > 0)
        );
    }

    // Add column if missing
    function addColumn(col, def, cb) {
        hasColumn(col, exists => {
            if (exists) { console.log(`   ✓ column ${col} already present`); cb(); return; }
            db.query(`ALTER TABLE diary_entries ADD COLUMN ${col} ${def}`, err => {
                if (err) console.error(`   ❌ add ${col}:`, err.message);
                else     console.log(`   ✅ added column: ${col}`);
                cb();
            });
        });
    }

    // Drop index if it exists
    function dropIndex(idx, cb) {
        hasIndex(idx, exists => {
            if (!exists) { cb(); return; }
            db.query(`ALTER TABLE diary_entries DROP INDEX ${idx}`, err => {
                if (err) console.error(`   ❌ drop index ${idx}:`, err.message);
                cb();
            });
        });
    }

    // Sequential migrations
    // 1. page_number
    addColumn('page_number', 'INT NOT NULL DEFAULT 1', () => {
    // 2. type
    addColumn('type', "VARCHAR(10) NOT NULL DEFAULT 'personal'", () => {
    // 3. updated_at  (your old table had created_at instead)
    addColumn('updated_at', 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP', () => {
    // 4. Drop any old broken indexes, then add correct one
    dropIndex('unique_entry', () => {
    dropIndex('ux_user_page_type', () => {
        // Remove duplicate rows before adding unique key
        db.query(`
            DELETE d1 FROM diary_entries d1
            INNER JOIN diary_entries d2
               ON  d1.user_id=d2.user_id AND d1.page_number=d2.page_number
               AND d1.type=d2.type AND d1.id > d2.id
        `, () => {
            db.query(`
                ALTER TABLE diary_entries
                ADD UNIQUE KEY ux_user_page_type (user_id, page_number, type)
            `, err => {
                if (err) console.error('   ❌ unique key:', err.message);
                else     console.log('   ✅ unique index ready');
                console.log('✅  diary_entries fully ready\n');
            });
        });
    });});});});});
}

// ─── POST /register ───────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
    const { name, phone, email, gender, username, password } = req.body;
    if (!name || !phone || !email || !gender || !username || !password)
        return res.status(400).json({ message: 'All fields are required.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        db.query(
            'INSERT INTO users (name,phone,email,gender,username,password) VALUES (?,?,?,?,?,?)',
            [name, phone, email, gender, username, hash],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        const field = err.message.toLowerCase().includes('email') ? 'Email' : 'Username';
                        return res.status(409).json({ message: `${field} already taken.` });
                    }
                    return res.status(500).json({ message: 'Database error.' });
                }
                console.log(`✅  Registered: ${username}`);
                res.status(201).json({ message: 'Account created!', userId: result.insertId });
            }
        );
    } catch (e) { res.status(500).json({ message: 'Server error.' }); }
});

// ─── POST /login ──────────────────────────────────────────────────────────────
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ message: 'Username and password required.' });
    db.query('SELECT * FROM users WHERE username=?', [username], async (err, rows) => {
        if (err)          return res.status(500).json({ message: 'Database error.' });
        if (!rows.length) return res.status(401).json({ message: 'Invalid username or password.' });
        const user = rows[0];
        try {
            if (!(await bcrypt.compare(password, user.password)))
                return res.status(401).json({ message: 'Invalid username or password.' });
            const token = jwt.sign({ userId: user.id, username: user.username }, SECRET, { expiresIn: '8h' });
            console.log(`✅  Login: ${username}`);
            res.json({ message: 'Login successful!', token, userId: user.id, username: user.username, name: user.name });
        } catch (e) { res.status(500).json({ message: 'Server error.' }); }
    });
});

// ─── POST /save-diary ─────────────────────────────────────────────────────────
// Body: { page_number: int, type: 'personal'|'public', content: string }
app.post('/save-diary', auth, (req, res) => {
    let { page_number, type, content } = req.body;
    page_number = parseInt(page_number, 10);
    if (!page_number || page_number < 1)
        return res.status(400).json({ message: 'page_number must be a positive integer.' });
    if (!type || !['personal','public'].includes(type))
        return res.status(400).json({ message: 'type must be personal or public.' });
    content = (content == null) ? '' : String(content);

    console.log(`💾  save  user=${req.userId}  page=${page_number}  type=${type}  len=${content.length}`);

    // Note: do NOT mention updated_at explicitly – MySQL updates it automatically
    db.query(
        `INSERT INTO diary_entries (user_id, page_number, type, content)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE content = VALUES(content)`,
        [req.userId, page_number, type, content],
        (err, result) => {
            if (err) {
                console.error('❌  save error:', err.message);
                return res.status(500).json({ message: 'Save failed: ' + err.message });
            }
            console.log(`    saved OK  affectedRows=${result.affectedRows}`);
            res.json({ ok: true });
        }
    );
});

// ─── GET /get-diary/:type/:page ───────────────────────────────────────────────
app.get('/get-diary/:type/:page', auth, (req, res) => {
    const type = req.params.type;
    const page = parseInt(req.params.page, 10);
    if (!['personal','public'].includes(type) || !page || page < 1)
        return res.status(400).json({ message: 'Invalid type or page.' });

    console.log(`📖  load  user=${req.userId}  page=${page}  type=${type}`);

    // COALESCE handles both old tables (created_at) and new tables (updated_at)
    db.query(
        `SELECT content,
                COALESCE(updated_at, created_at) AS date_col
         FROM   diary_entries
         WHERE  user_id=? AND page_number=? AND type=?`,
        [req.userId, page, type],
        (err, rows) => {
            if (err) {
                console.error('❌  load error:', err.message);
                return res.status(500).json({ message: 'Load failed: ' + err.message });
            }
            if (!rows.length) {
                console.log('    → not found, returning empty');
                return res.json({ content: '', date: null });
            }
            console.log(`    → found  len=${(rows[0].content||'').length}`);
            res.json({ content: rows[0].content || '', date: rows[0].date_col });
        }
    );
});

// ─── GET /public-diary ────────────────────────────────────────────────────────
app.get('/public-diary', (req, res) => {
    db.query(`
        SELECT de.page_number, de.content,
               COALESCE(de.updated_at, de.created_at) AS updated_at,
               u.name, u.username
        FROM   diary_entries de
        JOIN   users u ON u.id = de.user_id
        WHERE  de.type='public' AND de.content IS NOT NULL AND de.content != ''
        ORDER  BY updated_at DESC LIMIT 200
    `, (err, rows) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        res.json(rows);
    });
});

// ─── GET /my-stats ────────────────────────────────────────────────────────────
app.get('/my-stats', auth, (req, res) => {
    db.query(
        `SELECT COUNT(*) AS pages,
                COALESCE(SUM(CHAR_LENGTH(content) - CHAR_LENGTH(REPLACE(content,' ','')) + 1), 0) AS words,
                MIN(COALESCE(updated_at, created_at)) AS first_date
         FROM   diary_entries
         WHERE  user_id=? AND content IS NOT NULL AND content != ''`,
        [req.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ message: 'DB error' });
            const r    = rows[0];
            const days = r.first_date
                ? Math.max(1, Math.round((Date.now() - new Date(r.first_date)) / 86400000))
                : 0;
            res.json({ pages: r.pages || 0, words: r.words || 0, days });
        }
    );
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n🚀  Inkwell  →  http://localhost:${PORT}/LOGIN.html\n`);
});