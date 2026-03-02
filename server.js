const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const SECRET_KEY = "super-secret-key-123";

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// НАЛАШТУВАННЯ ПОШТИ (Заміни на свої дані для реальних листів)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: 'твоя_пошта@gmail.com', pass: 'твій_пароль_додатка_google' }
});

const db = new sqlite3.Database('./events.db');

db.serialize(() => {
    db.run(`PRAGMA foreign_keys = ON`);
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, date TEXT, location TEXT, description TEXT, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    db.run(`CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, task_name TEXT, deadline TEXT, reminder TEXT, is_completed INTEGER DEFAULT 0, FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE)`);

    // ТАБЛИЦІ ДЛЯ КОЛАБОРАЦІЇ
    db.run(`CREATE TABLE IF NOT EXISTS event_coorganizers (event_id INTEGER, user_id INTEGER, PRIMARY KEY(event_id, user_id))`);
    db.run(`CREATE TABLE IF NOT EXISTS invitations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER,
        inviter_id INTEGER,
        invitee_email TEXT,
        status TEXT DEFAULT 'pending'
    )`);
});

// --- АВТОРИЗАЦІЯ ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: "Email вже зайнятий" });
            res.json({ success: true });
        });
    } catch (e) { res.status(500).json({ error: "Помилка сервера" }); }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin' && password === 'admin123') {
        const token = jwt.sign({ id: 'admin', role: 'admin' }, SECRET_KEY, { expiresIn: '24h' });
        return res.json({ token, is_admin: true });
    }
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Користувача не знайдено" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Невірний пароль" });
        const token = jwt.sign({ id: user.id, role: 'user', email: user.email }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, is_admin: false, email: user.email });
    });
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Немає доступу" });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Токен недійсний" });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Доступ тільки для адміністратора" });
    next();
};

// --- АДМІНКА ---
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    db.all('SELECT id, email FROM users WHERE email LIKE ?', [`%${req.query.search}%`], (err, users) => res.json(users || []));
});
app.get('/api/admin/users/:id/events', authenticateToken, isAdmin, (req, res) => {
    db.all('SELECT * FROM events WHERE user_id = ? ORDER BY id DESC', [req.params.id], (err, events) => {
        db.all('SELECT * FROM tasks', [], (err, tasks) => {
            events.forEach(event => event.tasks = tasks.filter(t => t.event_id === event.id));
            res.json(events);
        });
    });
});

// --- ЗАПРОШЕННЯ (INVITES) ---
// 1. Відправити запрошення
app.post('/api/events/:id/invite', authenticateToken, (req, res) => {
    const { email } = req.body;
    const eventId = req.params.id;

    db.get('SELECT title FROM events WHERE id = ? AND user_id = ?', [eventId, req.user.id], (err, event) => {
        if (!event) return res.status(403).json({ error: "Це не ваш івент" });

        db.run('INSERT INTO invitations (event_id, inviter_id, invitee_email) VALUES (?, ?, ?)', [eventId, req.user.id, email], function(err) {
            res.json({ success: true });

            // Відправляємо реальний лист (якщо налаштовано)
            transporter.sendMail({
                from: 'EventM',
                to: email,
                subject: `Запрошення до івенту: ${event.title}`,
                text: `Вас запросили взяти участь в івенті "${event.title}". Увійдіть у свій акаунт EventM, щоб прийняти запрошення!`
            }).catch(e => console.log("Пошта не налаштована, але запрошення в базі збережено."));
        });
    });
});

// 2. Отримати мої запрошення
app.get('/api/invitations', authenticateToken, (req, res) => {
    const query = `
        SELECT i.id, e.title, u.email as inviter_email 
        FROM invitations i
        JOIN events e ON i.event_id = e.id
        JOIN users u ON i.inviter_id = u.id
        WHERE i.invitee_email = ? AND i.status = 'pending'
    `;
    db.all(query, [req.user.email], (err, invites) => res.json(invites || []));
});

// 3. Відповісти на запрошення
app.post('/api/invitations/:id/respond', authenticateToken, (req, res) => {
    const { status } = req.body; // 'accepted' або 'rejected'
    db.get('SELECT event_id FROM invitations WHERE id = ?', [req.params.id], (err, invite) => {
        if (!invite) return res.status(404).json({ error: "Не знайдено" });

        db.run('UPDATE invitations SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
            if (status === 'accepted') {
                db.run('INSERT OR IGNORE INTO event_coorganizers (event_id, user_id) VALUES (?, ?)', [invite.event_id, req.user.id], () => res.json({ success: true }));
            } else {
                res.json({ success: true });
            }
        });
    });
});

// --- ІВЕНТИ ТА ТАСКИ ---
// --- ІВЕНТИ ТА ТАСКИ ---
app.get('/api/events', authenticateToken, (req, res) => {
    if (req.user.role === 'admin') return res.json([]);

    // Оновлений запит: тепер ми беремо ще й email автора (власника) івенту
    const queryEvents = `
        SELECT DISTINCT e.*, u.email as owner_email
        FROM events e
                 LEFT JOIN event_coorganizers ec ON e.id = ec.event_id
                 JOIN users u ON e.user_id = u.id
        WHERE e.user_id = ? OR ec.user_id = ? ORDER BY e.id DESC
    `;

    db.all(queryEvents, [req.user.id, req.user.id], (err, events) => {
        if (err) return res.status(500).json({ error: err.message });

        db.all('SELECT * FROM tasks', [], (err, tasks) => {
            if (err) return res.status(500).json({ error: err.message });

            // Шукаємо пошти всіх співорганізаторів
            const queryCoorgs = `
                SELECT ec.event_id, u.email 
                FROM event_coorganizers ec
                JOIN users u ON ec.user_id = u.id
            `;

            db.all(queryCoorgs, [], (err, coorgs) => {
                if (err) return res.status(500).json({ error: err.message });

                // Збираємо все до купи
                events.forEach(event => {
                    event.tasks = tasks.filter(t => t.event_id === event.id);
                    event.coorganizers = coorgs
                        .filter(c => c.event_id === event.id)
                        .map(c => c.email);
                });

                res.json(events);
            });
        });
    });
});

app.post('/api/events', authenticateToken, (req, res) => {
    const { title, date, location, description } = req.body;
    db.run('INSERT INTO events (user_id, title, date, location, description) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, title, date, location, description], function(err) { res.json({ id: this.lastID }); });
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM events WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err) => res.json({ success: true }));
});

app.post('/api/events/:id/tasks', authenticateToken, (req, res) => {
    const { task_name, deadline, reminder } = req.body;
    db.run('INSERT INTO tasks (event_id, task_name, deadline, reminder) VALUES (?, ?, ?, ?)',
        [req.params.id, task_name, deadline, reminder], function(err) { res.json({ id: this.lastID }); });
});

app.put('/api/tasks/:id/toggle', authenticateToken, (req, res) => {
    db.run('UPDATE tasks SET is_completed = ? WHERE id = ?',
        [req.body.is_completed ? 1 : 0, req.params.id], (err) => res.json({ success: true }));
});

app.listen(3000, () => console.log('Сервер: http://localhost:3000'));