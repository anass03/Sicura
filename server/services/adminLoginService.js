// services/adminLoginService.js
// Manages pending dashboard login approvals via Telegram
const crypto = require("crypto");

const TIMEOUT_MS = 60 * 1000; // 60s to approve

// code -> { admin, resolve, reject, timer, promise }
const pending = new Map();
// adminId -> code
const pendingByAdminId = new Map();

function createPending(admin) {
    // evita di creare più pending per lo stesso admin
    const existingCode = pendingByAdminId.get(admin.id);
    if (existingCode) {
        const existing = pending.get(existingCode);
        if (existing) {
            return { code: existingCode, promise: existing.promise };
        }
        pendingByAdminId.delete(admin.id);
    }

    const code = crypto.randomUUID();

    let resolveFn;
    let rejectFn;
    const promise = new Promise((resolve, reject) => {
        resolveFn = resolve;
        rejectFn = reject;
    });

    const timer = setTimeout(() => {
        pending.delete(code);
        rejectFn(new Error("Login approval timed out"));
    }, TIMEOUT_MS);

    pending.set(code, {
        admin,
        resolve: resolveFn,
        reject: rejectFn,
        timer,
        promise
    });
    pendingByAdminId.set(admin.id, code);

    return { code, promise };
}

function getPending(code) {
    return pending.get(code) || null;
}

function getPendingForAdmin(adminId) {
    const code = pendingByAdminId.get(adminId);
    if (!code) return null;
    const entry = pending.get(code);
    if (!entry) {
        pendingByAdminId.delete(adminId);
        return null;
    }
    return { code, ...entry };
}

function resolve(code, approved) {
    const entry = pending.get(code);
    if (!entry) return false;

    clearTimeout(entry.timer);
    pending.delete(code);
    pendingByAdminId.delete(entry.admin.id);
    entry.resolve({ approved });
    return true;
}

function reject(code, reason) {
    const entry = pending.get(code);
    if (!entry) return false;

    clearTimeout(entry.timer);
    pending.delete(code);
    pendingByAdminId.delete(entry.admin.id);
    entry.reject(new Error(reason || "Login approval rejected"));
    return true;
}

module.exports = {
    createPending,
    getPending,
    getPendingForAdmin,
    resolve,
    reject
};
