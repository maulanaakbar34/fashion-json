const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        // 401 Unauthorized: Token tidak ditemukan
        return res.status(401).json({ error: 'Akses ditolak, token tidak ditemukan' });
    }

    // Verifikasi token
    jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
        if (err) {
            console.error("JWT Verify Error:", err.message);
            return res.status(403).json({ error: 'Token tidak valid atau kedaluwarsa' });
        }

        req.user = decodedPayload.user;
        
        // Lanjutkan ke handler rute berikutnya
        next();
    });
}

module.exports = authenticateToken;