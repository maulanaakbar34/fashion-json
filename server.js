require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./database.js"); // Asumsi koneksi database
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const { authenticateToken, authorizeRole } = require("./middleware/auth.js"); // Asumsi middleware ada
const app = express();
const PORT = process.env.PORT || 3300;

app.use(cors());
app.use(express.json());

// Endpoint Status
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "api-fashion" });
});

// --- AUTENTIKASI ---

// Registrasi Pengguna Biasa
app.post("/auth/register", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Username dan password (min 6 char) harus diisi" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
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

// Registrasi Admin
app.post("/auth/register-admin", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Username dan password (min 6 char) harus diisi" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
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

// Login (Melengkapi bagian yang terpotong)
app.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password harus diisi" });
  }

  try {
    const sql = "SELECT id, username, password, role FROM users WHERE username = $1";
    const result = await db.query(sql, [username.toLowerCase()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const payload = {
      user: { id: user.id, username: user.username, role: user.role },
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login berhasil", token: token });
  } catch (err) {
    next(err);
  }
});

// --- FASHION CRUD ---

// GET Semua Produk Fashion
app.get("/fashion", async (req, res, next) => {
  // FIX: Tambahkan tanda kutip dan ganti tabel/kolom
  const sql = "SELECT * FROM fashion ORDER BY sku ASC";
  try {
    const result = await db.query(sql);
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// GET Produk Fashion Berdasarkan SKU
app.get("/fashion/:sku", async (req, res, next) => {
  const sql = "SELECT * FROM fashion WHERE sku = $1";
  try {
    const result = await db.query(sql, [req.params.sku.toUpperCase()]); // Ganti kd_produk ke sku
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// POST Tambah Produk Fashion
app.post("/fashion", authenticateToken, async (req, res, next) => {
  const { sku, productName, price, isAvailable } = req.body;
  if (!sku || !productName || !price || isAvailable === undefined) {
    return res
      .status(400)
      .json({ error: "sku, productName, price, dan isAvailable wajib diisi." });
  } 

  // FIX: Validasi isAvailable sebagai boolean
  if (typeof isAvailable !== "boolean") {
    return res
      .status(400)
      .json({ error: "isAvailable harus berupa boolean (true atau false)." });
  } 

  const sql = "INSERT INTO fashion (sku, \"productName\", price, \"isAvailable\") VALUES ($1, $2, $3, $4) RETURNING *";
  try {
    const result = await db.query(sql, [
      sku.toUpperCase(), 
      productName, 
      price,
      isAvailable, // Boolean value
    ]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "SKU produk sudah digunakan" }); // Ganti error message
    }
    next(err);
  }
});

// PUT Update Produk Fashion
app.put(
  "/fashion/:sku", // Ganti rute
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const { productName, price, isAvailable } = req.body;
    const sku = req.params.sku.toUpperCase(); // Ganti kdProduk ke sku

    if (isAvailable !== undefined && typeof isAvailable !== "boolean") {
      return res
        .status(400)
        .json({ error: "isAvailable harus berupa boolean (true atau false)." });
    } 

    if (
      productName === undefined && 
      price === undefined &&
      isAvailable === undefined
    ) {
      return res.status(400).json({
        error:
          "Setidaknya satu field (productName, price, atau isAvailable) harus diisi untuk update.",
      });
    }

    let updateFields = [];
    let queryParams = [];
    let paramCounter = 1;

    if (productName !== undefined) {
      updateFields.push(`"productName" = $${paramCounter++}`); // Kolom productName
      queryParams.push(productName);
    }
    if (price !== undefined) {
      updateFields.push(`price = $${paramCounter++}`); // Kolom price
      queryParams.push(price);
    }
    if (isAvailable !== undefined) {
      updateFields.push(`"isAvailable" = $${paramCounter++}`); // Kolom isAvailable
      queryParams.push(isAvailable);
    }

    const sql = `UPDATE fashion SET ${updateFields.join(
      ", "
    )} WHERE sku = $${paramCounter} RETURNING *`;

    queryParams.push(sku);

    try {
      const result = await db.query(sql, queryParams);
      if (result.rowCount === 0) {
        return res
          .status(404)
          .json({ error: "Produk tidak ditemukan untuk diperbarui." });
      }
      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

// DELETE Hapus Produk Fashion
app.delete("/fashion/:sku", [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const sku = req.params.sku.toUpperCase(); 
    const sql = "DELETE FROM fashion WHERE sku = $1 RETURNING *"; 
    try {
      const result = await db.query(sql, [sku]); 
      if (result.rowCount === 0) {
        return res
          .status(404)
          .json({ error: "Produk tidak ditemukan untuk dihapus." });
      }
      res.status(204).send(); 
    } catch (err) {
      next(err);
    }
  }
);

// Rute Default
app.get("/", (req, res) => {
  res.send("API Fashion berjalan. Akses /fashion untuk data produk.");
});

app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

// Penanganan Error Server Global
app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err.stack);
  res.status(500).json({ error: "Terjadi kesalahan pada server" });
});

// Mulai Server
app.listen(PORT, () => {
  console.log(`API Fashion berjalan di http://localhost:${PORT}`);
});