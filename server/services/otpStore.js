// services/otpStore.js
// Gestione OTP condiviso: persistenza su disco e generazione.
const fs = require("fs");
const path = require("path");

const OTP_FILE = path.join(__dirname, "..", "data", "otp.json");

let cachedOtp = null;
let cachedUpdatedAt = null;

function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000);
}

function loadFromDisk() {
    try {
        if (!fs.existsSync(OTP_FILE)) {
            cachedOtp = null;
            cachedUpdatedAt = null;
            return;
        }
        const raw = fs.readFileSync(OTP_FILE, "utf8");
        if (!raw.trim()) {
            cachedOtp = null;
            cachedUpdatedAt = null;
            return;
        }
        const parsed = JSON.parse(raw);
        cachedOtp = typeof parsed.otp === "number" ? parsed.otp : null;
        cachedUpdatedAt = parsed.updatedAt || null;
    } catch (err) {
        console.error("[otpStore] Error loading OTP:", err);
        cachedOtp = null;
        cachedUpdatedAt = null;
    }
}

function saveToDisk() {
    try {
        const dir = path.dirname(OTP_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(
            OTP_FILE,
            JSON.stringify(
                { otp: cachedOtp, updatedAt: cachedUpdatedAt },
                null,
                2
            ),
            "utf8"
        );
    } catch (err) {
        console.error("[otpStore] Error saving OTP:", err);
    }
}

function ensureLoaded() {
    if (cachedOtp === null && cachedUpdatedAt === null) {
        loadFromDisk();
    }
}

function hasOtp() {
    ensureLoaded();
    return typeof cachedOtp === "number" && !!cachedUpdatedAt;
}

function getOtp() {
    ensureLoaded();
    return { otp: cachedOtp, updatedAt: cachedUpdatedAt };
}

function setOtp(otpValue, timestamp = new Date().toISOString()) {
    cachedOtp = otpValue;
    cachedUpdatedAt = timestamp;
    saveToDisk();
    return { otp: cachedOtp, updatedAt: cachedUpdatedAt };
}

function generateAndSave() {
    const otpValue = generateOtp();
    const timestamp = new Date().toISOString();
    return setOtp(otpValue, timestamp);
}

module.exports = {
    hasOtp,
    getOtp,
    setOtp,
    generateAndSave,
};
