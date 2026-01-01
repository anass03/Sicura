function isLocal(addr) {
    if (!addr) return false;
    if (addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1") return true;
    if (addr.startsWith("::ffff:127.")) return true;
    if (addr.startsWith("127.")) return true;
    return false;
}

function requireLocalhost(req, res, next) {
    const header = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const remote = req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip;
    if (!isLocal(header) && !isLocal(remote)) {
        return res.status(403).json({ error: "Lab control allowed only from localhost" });
    }
    return next();
}

module.exports = { requireLocalhost };
