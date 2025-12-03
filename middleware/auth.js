const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: 'Akses ditolak, token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
        if (err) {
            console.error("JWT Verify Error:", err.message);
            return res.status(403).json({ error: 'Token tidak valid atau kedaluwarsa' });
        }
        // Menyimpan payload user (termasuk role)
        req.user = decodedPayload.user;
        next();
    });
}

// Middleware Autorisasi (BARU)
function authorizeRole(role) {
    return (req, res, next) => {
        // Middleware ini HARUS dijalankan SETELAH authenticateToken
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: 'Akses Dilarang: Peran tidak memadai' });
        }
        next();  // peran cocok, lanjutkan
    };
}

module.exports = {
    authenticateToken,
    authorizeRole
};