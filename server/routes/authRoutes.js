// routes/authRoutes.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const userStore = require("../services/userStore");
const telegramService = require("../services/telegramService");
const accessService = require("../services/accessService");
const { JWT_SECRET } = require("../config");
const { requireAdmin } = require("../middleware/authMiddleware");
const crypto = require("crypto");

const router = express.Router();

// ---------------- Brute-force protection (in-memory) ----------------
// Note: This is process-local. If you run multiple instances, use a shared store (Redis) instead.
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS_PER_IP = 25;
const MAX_ATTEMPTS_PER_USERNAME = 10;
const BASE_LOCK_MS = 30 * 1000; // 30s
const MAX_LOCK_MS = 30 * 60 * 1000; // 30m

const loginAttemptsByIp = new Map();        // ip -> entry
const loginAttemptsByUsername = new Map();  // normalizedUsername -> entry

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeLoginUsername(value) {
    if (!value) return "";
    return String(value).trim().toLowerCase();
}

function getClientIp(req) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim()) {
        return xff.split(",")[0].trim();
    }
    return req.ip || req.connection?.remoteAddress || "unknown";
}

function getOrInitEntry(map, key, now) {
    const entry = map.get(key);
    if (!entry) {
        const fresh = { count: 0, firstAt: now, lastAt: now, lockedUntil: 0 };
        map.set(key, fresh);
        return fresh;
    }

    // window reset
    if (now - entry.firstAt > LOGIN_WINDOW_MS && now >= entry.lockedUntil) {
        entry.count = 0;
        entry.firstAt = now;
    }
    entry.lastAt = now;
    return entry;
}

function isLocked(entry, now) {
    return entry && entry.lockedUntil && now < entry.lockedUntil;
}

function registerFailure(entry, now, threshold) {
    entry.count += 1;
    entry.lastAt = now;
    if (entry.count >= threshold) {
        const over = entry.count - threshold;
        const lockMs = Math.min(MAX_LOCK_MS, BASE_LOCK_MS * Math.pow(2, over));
        entry.lockedUntil = Math.max(entry.lockedUntil || 0, now + lockMs);
    }
}

function clearEntry(map, key) {
    map.delete(key);
}

// 👉 dice se esiste almeno un admin
router.get("/admin-status", (req, res) => {
    const admins = userStore.getAdmins();
    res.json({ hasAdmin: admins.length > 0 });
});

// registrazione utente normale (pubblica) - eventualmente usata da altre parti
router.post("/register-user", (req, res) => {
    const { username, telegramUsername } = req.body;

    if (!username || !telegramUsername) {
        return res
            .status(400)
            .json({ error: "username and telegramUsername are required" });
    }

    try {
        const user = userStore.addUser({ username, telegramUsername });
        if (telegramService.notifyUserRegistered) {
            telegramService.notifyUserRegistered(user);
        }
        const otpInfo = accessService.ensureInitialOtp?.();
        if (otpInfo && telegramService.notifyOtpForUser) {
            telegramService.notifyOtpForUser(user, otpInfo, "registration");
        }
        res.json({ ok: true, user: { id: user.id, username: user.username } });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// registrazione admin:
// - se non esistono admin, chiunque può registrare il primo
// - se esistono già admin, serve token admin (middleware)
router.post("/register-admin",
    (req, res, next) => {
        const admins = userStore.getAdmins();
        if (admins.length === 0) {
            return next(); // nessun admin, nessun controllo
        }
        return requireAdmin(req, res, next);
    },
    (req, res) => {
        const { username, password, phone, telegramUsername } = req.body;
        if (!username || !password || !phone || !telegramUsername) {
            return res.status(400).json({
                error: "username, password, phone and telegramUsername are required"
            });
        }

        const passwordHash = bcrypt.hashSync(password, 10);

        try {
            const admin = userStore.addAdmin({
                username,
                passwordHash,
                phone,
                telegramUsername
            });
            let otpInfo = null;
            if (accessService.ensureInitialOtp) {
                otpInfo = accessService.ensureInitialOtp();
            }
            if (telegramService.notifyUserRegistered) {
                telegramService.notifyUserRegistered(admin);
            }
            if (otpInfo && telegramService.notifyOtpForUser) {
                telegramService.notifyOtpForUser(admin, otpInfo, "initial-admin");
            }
            res.json({
                ok: true,
                admin: { id: admin.id, username: admin.username },
                otp: otpInfo?.otp || null,
                otpUpdatedAt: otpInfo?.updatedAt || null
            });
        } catch (e) {
            res.status(400).json({ error: e.message });
        }
    }
);

// login admin
router.post("/login", async (req, res) => {
    const now = Date.now();
    const ip = getClientIp(req);
    const normalizedUsername = normalizeLoginUsername(req.body?.username);

    const ipEntry = getOrInitEntry(loginAttemptsByIp, ip, now);
    const userEntry = getOrInitEntry(loginAttemptsByUsername, normalizedUsername || "unknown", now);

    if (isLocked(ipEntry, now) || isLocked(userEntry, now)) {
        const lockedUntil = Math.max(ipEntry.lockedUntil || 0, userEntry.lockedUntil || 0);
        const retryAfterSec = Math.max(1, Math.ceil((lockedUntil - now) / 1000));
        res.setHeader("Retry-After", String(retryAfterSec));
        return res.status(429).json({
            error: "Too many login attempts. Please try again later.",
            retryAfterSec
        });
    }

    const { username, password } = req.body;
    if (!username || !password)
        return res
            .status(400)
            .json({ error: "username and password are required" });

    // Also count malformed/empty attempts.
    if (!normalizedUsername) {
        registerFailure(ipEntry, now, MAX_ATTEMPTS_PER_IP);
    }

    const admin = userStore.findAdminByUsername(username);
    if (!admin || !admin.enabled) {
        registerFailure(ipEntry, now, MAX_ATTEMPTS_PER_IP);
        registerFailure(userEntry, now, MAX_ATTEMPTS_PER_USERNAME);
        await sleep(Math.min(1200, 150 + ipEntry.count * 50));
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const ok = bcrypt.compareSync(password, admin.passwordHash);
    if (!ok) {
        registerFailure(ipEntry, now, MAX_ATTEMPTS_PER_IP);
        registerFailure(userEntry, now, MAX_ATTEMPTS_PER_USERNAME);
        await sleep(Math.min(1200, 150 + userEntry.count * 70));
        return res.status(401).json({ error: "Invalid credentials" });
    }

    // success -> clear counters for this ip and username (best effort)
    clearEntry(loginAttemptsByIp, ip);
    clearEntry(loginAttemptsByUsername, normalizedUsername);

    // <<< NUOVO: genera una sessione unica per questo admin >>>
    const sessionId = crypto.randomUUID();
    userStore.setAdminSession(admin.id, sessionId);

    const token = jwt.sign(
        {
            sub: admin.id,
            role: "admin",
            username: admin.username,
            sid: sessionId,     // <- l'id di sessione è dentro il token
        },
        JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({
        token,
        admin: { username: admin.username },
    });
});


module.exports = router;
