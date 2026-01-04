// services/accessService.js
const fs = require("fs");
const path = require("path");
const userStore = require("./userStore");
const otpStore = require("./otpStore");

let mqttServiceRef = null;
let telegramServiceRef = null;

// currentRequest structure: { user, telegramUsername, timestamp, registered, enabled, userStatus }
let currentRequest = null;
let systemState = "WAITING";

let log = [];                // { user, decision, time, source, otp? }
let pendingUsers = [];
// ogni elemento: { id, username, telegramUsername, faceOk, telegramChatId }

const REGISTRATION_TIMEOUT_MS = 3 * 60 * 1000; // 5 minuti
const DELETE_TIMEOUT_MS = 30 * 1000; // 60 secondi


const MAX_LOG = 200;
const LOG_FILE = path.join(__dirname, "../data/accessLog.json");
const LOG_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 giorni
// DELETE pending: key = telegramUsername
const pendingDeletes = new Map();
const pendingDeleteTimeouts = new Map();

/* ---------- PERSISTENZA LOG ---------- */

function loadLogFromDisk() {
    try {
        if (!fs.existsSync(LOG_FILE)) {
            log = [];
            return;
        }
        const raw = fs.readFileSync(LOG_FILE, "utf8");
        const arr = JSON.parse(raw);
        const now = Date.now();
        log = (Array.isArray(arr) ? arr : []).filter(e => {
            if (!e.time) return false;
            const t = Date.parse(e.time);
            if (Number.isNaN(t)) return false;
            return now - t <= LOG_RETENTION_MS;
        });
    } catch (err) {
        console.error("[accessService] Error reading log:", err);
        log = [];
    }
}

function saveLogToDisk() {
    try {
        const dir = path.dirname(LOG_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(LOG_FILE, JSON.stringify(log, null, 2));
    } catch (err) {
        console.error("[accessService] Error saving log:", err);
    }
}

function pushLog(entry) {
    log.push(entry);
    if (log.length > MAX_LOG) log = log.slice(-MAX_LOG);
    saveLogToDisk();
}

/* ---------- INIT ---------- */

function init(mqttService, telegramService) {
    mqttServiceRef = mqttService;
    telegramServiceRef = telegramService;

    loadLogFromDisk();

    if (telegramServiceRef && telegramServiceRef.onDecision) {
        telegramServiceRef.onDecision((decision, source) =>
            handleDecision(decision, source)
        );
    }
}

function ensureOtpAvailable() {
    if (otpStore.hasOtp()) {
        return otpStore.getOtp();
    }
    console.warn("[accessService] OTP not found. Generating a new one to keep the system consistent.");
    return regenerateOtp("auto");
}

function regenerateOtp(reason = "manual") {
    const info = otpStore.generateAndSave();
    if (telegramServiceRef?.notifyOtpChanged) {
        telegramServiceRef.notifyOtpChanged(info, reason);
    }
    return info;
}

function ensureInitialOtp() {
    if (otpStore.hasOtp()) return otpStore.getOtp();
    return regenerateOtp("initial");
}

function getOtpInfo() {
    return ensureOtpAvailable();
}

function sendOtpToUser(user, reason = "registration") {
    if (!user || !user.telegramChatId) return;
    const info = ensureOtpAvailable();
    if (telegramServiceRef?.notifyOtpForUser) {
        telegramServiceRef.notifyOtpForUser(user, info, reason);
    }
}

/* ---------- RICHIESTA DA ARDUINO ---------- */

function handleAccessRequest(payload) {
    const nowIso = new Date().toISOString();

    // user univoco tramite username Telegram (normalizzato)
    const normalizedTelegram = userStore.normalizeTelegramUsername(payload.telegramUsername || "");
    const userRec = userStore.findUserByTelegramUsername(normalizedTelegram);

    const exists    = !!userRec;
    const registered = !!(userRec && userRec.telegramChatId);
    const enabled   = userRec ? !!userRec.enabled : null;
    const displayUser = userRec?.telegramUsername || normalizedTelegram || "Unknown";

    // Separate "systemState" (UI flow) from user status (context).
    // We keep systemState = WAITING for any incoming request, and expose the user status in currentRequest.
    let userStatus = "UNREGISTERED";
    if (exists && !enabled) userStatus = "DISABLED";
    else if (exists && registered && enabled) userStatus = "REGISTERED";
    else if (exists) userStatus = "UNREGISTERED"; // exists but not fully registered

    currentRequest = {
        user: displayUser,
        telegramUsername: normalizedTelegram || payload.telegramUsername || null,
        timestamp: nowIso,
        registered,
        enabled,
        userStatus
    };

    systemState = "WAITING";

    pushLog({
        user: currentRequest.user,
        decision: systemState,
        time: nowIso,
        source: "arduino"
    });

    if (telegramServiceRef && telegramServiceRef.notifyAccessRequest) {
        telegramServiceRef.notifyAccessRequest(currentRequest);
    }
}

/* ---------- DECISIONE (WEB o TELEGRAM) ---------- */
function handleDecision(decision, source) {
    if (decision !== "OK" && decision !== "KO") {
        console.warn("[accessService] Decisione non valida:", decision);
        return;
    }
    if (!currentRequest) {
        console.log("[accessService] Nessuna richiesta in attesa, decisione ignorata.");
        return;
    }


    // utente registrato, ignoriamo e facciamo lavorare solo Telegram.
    if (currentRequest.registered && source === "web" && currentRequest.enabled) {
        console.log(
            "[accessService] Decisione web ignorata: utente registrato. " +
            "Registered users must approve/deny from Telegram."
        );
        return;
    }

    const timestamp = new Date().toISOString();
    const { otp } = ensureOtpAvailable();

    const payload = { decision, otp, timestamp };

    console.log(
        "[accessService] handleDecision:",
        decision,
        "otp:",
        otp,
        "source:",
        source
    );

    if (mqttServiceRef) {
        console.log(
            "[accessService] PUB MQTT accesso/decisione:",
            payload
        );
        mqttServiceRef.publishDecision(payload);
    }

    systemState = decision === "OK" ? "ACCESS_GRANTED" : "ACCESS_DENIED";

    pushLog({
        user: currentRequest.user,
        decision,
        otp,
        time: timestamp,
        source
    });

    currentRequest = null;
}
function notifyUserUpdateToArduino(action, user) {
    if (!mqttServiceRef || !mqttServiceRef.publishUserUpdate) {
        console.warn("[accessService] mqttServiceRef.publishUserUpdate non disponibile");
        return;
    }

    // FASE 1: admin clicca "aggiungi utente" → START_ENROLL
    if (action === "START_ENROLL") {
        const now = Date.now();
        const pending = {
            id: now.toString(),   // id temporaneo
            username: user.username,
            telegramUsername: user.telegramUsername,
            faceOk: false,
            telegramChatId: null,
            status: "PENDING",
            message: "",
            createdAt: now,
            expiresAt: now + REGISTRATION_TIMEOUT_MS,
            updatedAt: now
        };

        pendingUsers.push(pending);
        console.log("[accessService] startUserEnrollment, pending:", pending);

        const payload = {
            action: "START_ENROLL",
            telegramUsername: pending.telegramUsername,
            timestamp: new Date().toISOString()
        };

        mqttServiceRef.publishUserUpdate(payload);
        return; // non proseguire sotto
    }

    // ENABLE, DISABLE
    const payload = {
        action,
        username: user.username || null,
        telegramUsername: user.telegramUsername || null,
        enabled: typeof user.enabled === "boolean" ? user.enabled : undefined,
        timestamp: new Date().toISOString()
    };

    mqttServiceRef.publishUserUpdate(payload);
}

function expirePendingIfNeeded(pending) {
    if (!pending) return false;
    if (pending.status === "DONE" || pending.status === "FAILED") return false;
    if (!pending.expiresAt) return false;
    if (Date.now() <= pending.expiresAt) return false;

    pending.status = "FAILED";
    pending.message = "⏱️ Registration timed out. Please start again.";
    pending.updatedAt = Date.now();

    setTimeout(() => {
        pendingUsers = pendingUsers.filter(u => u.id !== pending.id);
    }, 15000);

    return true;
}

function handleFaceEnrollResult(payload) {
    const { telegramUsername, success } = payload;

    const pending = pendingUsers.find(u => u.telegramUsername === telegramUsername);
    if (!pending) {
        console.warn("[accessService] ENROLL_RESULT ma nessun pending per", telegramUsername);
        return;
    }

    if (expirePendingIfNeeded(pending)) return;

    pending.updatedAt = Date.now();

    if (!success) {
        pending.status = "FAILED";
        pending.message = "⛔ Face enrollment failed on the device.";
        console.warn("[accessService] ENROLL_RESULT fallito per", telegramUsername);

        // opzionale: rimuovi dopo qualche secondo così la dashboard fa in tempo a leggerlo
        setTimeout(() => {
            const i = pendingUsers.findIndex(u => u.telegramUsername === telegramUsername);
            if (i !== -1) pendingUsers.splice(i, 1);
        }, 15000);

        return;
    }

    pending.faceOk = true;
    pending.message = "✅ Face enrolled successfully.";
    console.log("[accessService] Face OK per", telegramUsername);

    tryFinalizeUser(pending);
}

function handleDeleteResult(payload) {
    const { action, telegramUsername, success } = payload || {};

    if (action && action !== "DELETE_RESULT") {
        console.warn("[accessService] handleDeleteResult ricevuto action diversa:", action);
        return;
    }

    if (!telegramUsername) {
        console.warn("[accessService] DELETE_RESULT senza telegramUsername:", payload);
        return;
    }

    const pending = pendingDeletes.get(telegramUsername);
    if (!pending) {
        console.warn("[accessService] DELETE_RESULT ma nessuna delete pending per", telegramUsername);
        return;
    }

    const t = pendingDeleteTimeouts.get(telegramUsername);
    if (t) {
        clearTimeout(t);
        pendingDeleteTimeouts.delete(telegramUsername);
    }

    pending.updatedAt = Date.now();

    if (!success) {
        pending.status = "FAILED";
        pending.message = "⛔ Deletion failed on the device.";
        console.warn("[accessService] DELETE_RESULT fallito per", telegramUsername);

        // tienilo 15s così la dashboard lo vede
        setTimeout(() => pendingDeletes.delete(telegramUsername), 15000);
        return;
    }

    // ✅ Arduino OK → ora cancella lato server
    const ok = userStore.deleteUser(pending.userId);
    if (!ok) {
        pending.status = "FAILED";
        pending.message = "⛔ Device OK, but server-side deletion failed.";
        setTimeout(() => pendingDeletes.delete(telegramUsername), 15000);
        return;
    }

    pending.status = "DONE";
    pending.message = "✅ User deleted successfully.";
    console.log("[accessService] User deleted server-side for", telegramUsername);

    // tienilo 15s così la dashboard può mostrare il messaggio
    setTimeout(() => pendingDeletes.delete(telegramUsername), 15000);
}

function notifyTelegramStart(telegramUsername, chatId) {
    const pending = pendingUsers.find(
        (u) => u.telegramUsername === telegramUsername
    );

    if (!pending) {
        console.log(
            "[accessService] /start da",
            telegramUsername,
            "ma non è in pending. Gestisco con la logica normale."
        );
        return "NO_PENDING";
    }

    if (expirePendingIfNeeded(pending)) return "NO_PENDING";

    pending.telegramChatId = chatId;
    console.log("[accessService] Telegram /start per pending user:", pending);

    pending.status = "PENDING";
    pending.message = "✅ Telegram linked successfully.";
    pending.updatedAt = Date.now();

    const finalized = tryFinalizeUser(pending);
    return finalized ? "FINALIZED" : "WAIT_FACE";
}

function tryFinalizeUser(pending) {
    if (expirePendingIfNeeded(pending)) return false;
    if (!pending.faceOk || !pending.telegramChatId) return false;

    let user;
    try {
        user = userStore.addUser({
            username: pending.username,
            telegramUsername: pending.telegramUsername,
            telegramChatId: pending.telegramChatId,
            enabled: true,
            faceRegistered: true
        });
    } catch (e) {
        pending.status = "FAILED";
        pending.message = `⛔ Registration failed: ${e.message || "Unknown error"}`;
        pending.updatedAt = Date.now();
        setTimeout(() => {
            pendingUsers = pendingUsers.filter(u => u.id !== pending.id);
        }, 15000);
        return false;
    }

   telegramServiceRef?.notifyUserRegistered?.(user);
    sendOtpToUser(user, "registration");

    // ✅ PRIMA setti lo stato (così la dashboard lo vede)
    pending.status = "DONE";
    pending.message = "✅ Registration completed.";
    pending.updatedAt = Date.now();

    // ✅ POI rimuovi dopo 15s
    setTimeout(() => {
        pendingUsers = pendingUsers.filter(u => u.id !== pending.id);
    }, 15000);

    console.log("[accessService] User created:", user);
    return true;
}


function getPendingUsers() {
    // Applica timeout anche quando la dashboard interroga lo stato.
    pendingUsers.forEach(expirePendingIfNeeded);
    return pendingUsers;
}

function hasPendingRequest() {
    return !!currentRequest;
}

function getCurrentRequest() {
    return currentRequest;
}
/* ---------- STATUS ---------- */

function getStatus() {
    const { otp, updatedAt } = otpStore.getOtp();
    return {
        systemState,
        currentRequest,
        log,
        lastOtp: otp,
        lastOtpTime: updatedAt
    };
}
function requestDeleteUser(user) {
    if (!user?.telegramUsername) {
        throw new Error("User has no telegramUsername");
    }

    const key = user.telegramUsername;

    if (pendingDeletes.has(key)) {
        return false; // già in corso
    }

    const now = Date.now();
    const pending = {
        userId: user.id,
        telegramUsername: key,
        status: "PENDING",
        message: "🕒 Deletion in progress…",
        createdAt: now,
        expiresAt: now + DELETE_TIMEOUT_MS,
        updatedAt: now,
    };

    const timeout = setTimeout(() => {
        const cur = pendingDeletes.get(key);
        if (!cur) {
            pendingDeleteTimeouts.delete(key);
            return;
        }
        if (cur.status !== "PENDING") return;
        if (typeof cur.expiresAt === "number" && Date.now() < cur.expiresAt) return;

        cur.status = "FAILED";
        cur.message = "⏱️ Deletion cancelled: no confirmation received from the device.";
        cur.updatedAt = Date.now();

        pendingDeleteTimeouts.delete(key);
        setTimeout(() => pendingDeletes.delete(key), 15000);
    }, DELETE_TIMEOUT_MS + 100);
    pendingDeleteTimeouts.set(key, timeout);

    pendingDeletes.set(key, pending);

    // invia comando a Arduino via MQTT
    notifyUserUpdateToArduino("DELETE", user);

    return true;
}

function expirePendingDeleteIfNeeded(pending) {
    if (!pending) return false;
    if (pending.status === "DONE" || pending.status === "FAILED") return false;
    if (!pending.expiresAt) return false;
    if (Date.now() <= pending.expiresAt) return false;

    pending.status = "FAILED";
    pending.message = "⏱️ Deletion cancelled: no confirmation received from the device.";
    pending.updatedAt = Date.now();

    const t = pendingDeleteTimeouts.get(pending.telegramUsername);
    if (t) {
        clearTimeout(t);
        pendingDeleteTimeouts.delete(pending.telegramUsername);
    }

    setTimeout(() => pendingDeletes.delete(pending.telegramUsername), 15000);
    return true;
}

function getPendingDeletes() {
    Array.from(pendingDeletes.values()).forEach(expirePendingDeleteIfNeeded);
    return Array.from(pendingDeletes.values());
}

module.exports = {
    init,
    handleAccessRequest,
    handleDecision,
    getStatus,
    hasPendingRequest,
    getPendingUsers,
    notifyUserUpdateToArduino,
    notifyTelegramStart,
    handleFaceEnrollResult,
    handleDeleteResult,
    requestDeleteUser,
    getPendingDeletes,
    regenerateOtp,
    ensureInitialOtp,
    getOtpInfo
};
