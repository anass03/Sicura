// middleware/authMiddleware.js
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");
const userStore = require("../services/userStore");

function requireAdmin(req, res, next) {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

    if (!token) {
        return res.status(401).json({ error: "Missing token" });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);

        if (payload.role !== "admin") {
            return res.status(403).json({ error: "Not authorized" });
        }

        const admin = userStore.findAdminById(payload.sub);
        if (!admin || !admin.enabled) {
            return res.status(401).json({ error: "Invalid admin" });
        }

        // controllo singola sessione
        if (admin.sessionId && payload.sid !== admin.sessionId) {
            return res.status(401).json({ error: "Session is no longer valid" });
        }

        req.user = { id: admin.id, username: admin.username, role: "admin" };
        next();
    } catch (err) {
        res.clearCookie("token"); // ⬅️ FONDAMENTALE
        return res.status(401).json({ error: "Session expired" });
    }
}

module.exports = { requireAdmin };
