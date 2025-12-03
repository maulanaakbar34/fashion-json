require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./database.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
const { authenticateToken, authorizeRole } = require('./middleware/auth.js');
const app = express(); 
const PORT = process.env.PORT || 3300;

app.use(cors());
app.use(express.json());

// routes
app.get('/status', (req, res) => {
    res.json({ ok: true, service: 'vendor-b-api (distro-fashion)' });
});



app.post('/auth/register', async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ error: 'Username dan password (min 6 char) harus diisi' });
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const sql = 'INSERT INTO users(username, password, role) VALUES($1, $2, $3) RETURNING id, username';
        const result = await db.query(sql, [username.toLowerCase(), hashedPassword, 'user']);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') { // Kode error unik PostgreSQL untuk duplikasi
            return res.status(409).json({ error: 'Username sudah digunakan' });
        }
        next(err);
    }
});

app.post('/auth/register-admin', async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ error: 'Username dan password (min 6 char) harus diisi' });
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const sql = 'INSERT INTO users(username, password, role) VALUES($1, $2, $3) RETURNING id, username';
        const result = await db.query(sql, [username.toLowerCase(), hashedPassword, 'admin']);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ error: 'Username sudah digunakan' });
        }
        next(err);
    }
});

app.post('/auth/login', async (req, res, next) => {
    const { username, password } = req.body;
    try {
        const sql = "SELECT * FROM users WHERE username=$1";
        const result = await db.query(sql, [username.toLowerCase()]);
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }
        const payload = { user: { id: user.id, username: user.username, role: user.role } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil', token: token });
    } catch (err) {
        next(err);
    }
});

// Masuk ke endpoint GET, POST, PUT, DELETE
app.get('/fashion', async (req, res, next) => {
    const sql = `SELECT sku, "productName", price, "isAvailable" FROM fashion ORDER BY sku ASC`;
    try {
        const result = await db.query(sql);
        // Mengembalikan data sesuai format Vendor B
        res.json(result.rows);
    } catch (err) {
        next(err);
    }
});

// GET u produk by sku
app.get('/fashion/:sku', async (req, res, next) => {
    const sql = `SELECT sku, "productName", price, "isAvailable" FROM fashion WHERE sku = $1`;
    try {
        const result = await db.query(sql, [req.params.sku]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Produk tidak ditemukan' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        next(err);
    }
});

// POST u menambahkan produk
app.post('/fashion', authenticateToken, async (req, res, next) => {
    // Memastikan input sesuai dengan CamelCase dan tipe data yang benar
    const { sku, productName, price, isAvailable } = req.body; 
    
    if (!sku || !productName || !price || isAvailable === undefined) {
        return res.status(400).json({ error: 'sku, productName, price, dan isAvailable wajib diisi' });
    }
    
    // Pastikan price adalah integer
    const parsedPrice = parseInt(price);
    if (isNaN(parsedPrice)) {
        return res.status(400).json({ error: 'price harus berupa angka/integer' });
    }
    
    const sql = `INSERT INTO fashion (sku, "productName", price, "isAvailable") VALUES ($1, $2, $3, $4) RETURNING *`;
    try {
        const result = await db.query(sql, [sku, productName, parsedPrice, isAvailable]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') { // Error duplikasi Primary Key (SKU)
            return res.status(409).json({ error: 'SKU sudah digunakan' });
        }
        next(err);
    }
});

// PUT u update data
app.put('/fashion/:sku', [authenticateToken, authorizeRole('admin')], async (req, res, next) => {
    const { productName, price, isAvailable } = req.body;
    
    if (!productName && !price && isAvailable === undefined) {
        return res.status(400).json({ error: 'Setidaknya salah satu field (productName, price, atau isAvailable) harus diisi untuk update' });
    }
    
    const sku = req.params.sku;
    
    // Query dinamis sederhana: update semua field yang ada di body
    const fields = [];
    const values = [];
    let queryIndex = 1;
    
    if (productName !== undefined) {
        fields.push(`"productName" = $${queryIndex++}`);
        values.push(productName);
    }
    if (price !== undefined) {
        const parsedPrice = parseInt(price);
         if (isNaN(parsedPrice)) {
            return res.status(400).json({ error: 'price harus berupa angka/integer' });
        }
        fields.push(`price = $${queryIndex++}`);
        values.push(parsedPrice);
    }
    if (isAvailable !== undefined) {
        fields.push(`"isAvailable" = $${queryIndex++}`);
        values.push(isAvailable);
    }

    if (fields.length === 0) {
        return res.status(400).json({ error: 'Tidak ada field yang valid untuk diupdate.' });
    }
    
    values.push(sku); // SKU adalah parameter terakhir untuk WHERE
    
    const sql = `UPDATE fashion SET ${fields.join(', ')} WHERE sku = $${queryIndex} RETURNING *`;

    try {
        const result = await db.query(sql, values);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Produk tidak ditemukan' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        next(err);
    }
});

// DELETE u hapuss data
app.delete('/fashion/:sku', [authenticateToken, authorizeRole('admin')], async (req, res, next) => {
    const sql = 'DELETE FROM fashion WHERE sku = $1 RETURNING *';
    try {
        const result = await db.query(sql, [req.params.sku]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Produk tidak ditemukan' });
        }
        res.status(204).send(); // Status 204 berhasil data terhapus
    } catch (err) {
        next(err);
    }
});

// === FALLBACK & ERROR HANDLING ===
app.use((req, res) => {
    res.status(404).json({ error: 'Rute tidak ditemukan' });
});

app.use((err, req, res, next) => {
    console.error('[SERVER ERROR]', err.stack);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

// Batas untuk menjalankann server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server aktif di http://localhost:${PORT}`);
});