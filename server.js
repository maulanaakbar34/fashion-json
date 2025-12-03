require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticateToken, authorizeRole } = require("./middleware/auth.js");

const app = express();
const PORT = process.env.PORT || 3300;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// status checking
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "fashion-api" });
});


app.post("/auth/register", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 6) {
    return res.status(400).json({
      error: "Username dan password (minimal 6 karakter) harus diisi",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";

    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "user",
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/register-admin", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 6) {
    return res.status(400).json({
      error: "Username dan password (minimal 6 karakter) harus diisi",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";

    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "admin",
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

app.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username.toLowerCase(),
    ]);
    const user = result.rows[0];

    if (!user) return res.status(401).json({ error: "Kredensial tidak valid" });

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(401).json({ error: "Kredensial tidak valid" });

    const payload = {
      user: { id: user.id, username: user.username, role: user.role },
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login berhasil", token });
  } catch (err) {
    next(err);
  }
});


// GET ALL
app.get("/fashion", async (req, res) => {
  try {
    const result = await db.query(
      `SELECT sku, "productName", price, "isAvailable" FROM fashion ORDER BY sku ASC`
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET BY SKU
app.get("/fashion/:sku", async (req, res) => {
  const { sku } = req.params;

  try {
    const result = await db.query(
      `SELECT sku, "productName", price, "isAvailable" FROM fashion WHERE sku = $1`,
      [sku]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Produk tidak ditemukan" });

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST (CREATE)
app.post("/fashion", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const { sku, productName, price, isAvailable } = req.body;

  if (!sku || !productName || price == null || isAvailable == null) {
    return res.status(400).json({ error: "Data tidak lengkap" });
  }

  try {
    const result = await db.query(
      `INSERT INTO fashion (sku, "productName", price, "isAvailable")
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [sku, productName, price, isAvailable]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "SKU sudah terdaftar" });
    }
    res.status(500).json({ error: err.message });
  }
});

// PUT (UPDATE)
app.put("/fashion/:sku", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const { sku } = req.params;
  const { productName, price, isAvailable } = req.body;

  if (!productName || price == null || isAvailable == null) {
    return res.status(400).json({
      error: "productName, price, dan isAvailable wajib diisi",
    });
  }

  try {
    const check = await db.query("SELECT * FROM fashion WHERE sku = $1", [sku]);

    if (check.rowCount === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    }

    const result = await db.query(
      `UPDATE fashion
       SET "productName" = $1, price = $2, "isAvailable" = $3
       WHERE sku = $4
       RETURNING *`,
      [productName, price, isAvailable, sku]
    );

    res.json({ message: "Produk berhasil diupdate", item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE
app.delete("/fashion/:sku", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const { sku } = req.params;

  try {
    const result = await db.query(
      `DELETE FROM fashion WHERE sku = $1 RETURNING *`,
      [sku]
    );

    if (result.rowCount === 0)
      return res.status(404).json({ error: "Produk tidak ditemukan" });

    res.json({
      message: "Produk berhasil dihapus",
      deleted: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
