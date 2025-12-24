// services/userStore.js
const fs = require("fs");
const path = require("path");

const DATA_FILE = path.join(__dirname, "..", "data", "users.json");

// Stato in memoria
let state = {
    admins: [],
    users: []
};

// ----- Caricamento / salvataggio su file -----
function load() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const raw = fs.readFileSync(DATA_FILE, "utf8");
            if (raw.trim().length > 0) {
                const parsed = JSON.parse(raw);
                state.admins = parsed.admins || [];
                state.users = parsed.users || [];
            }
        }
    } catch (e) {
        console.error("Error loading users.json:", e);
    }
}

function save() {
    try {
        fs.writeFileSync(
            DATA_FILE,
            JSON.stringify(
                {
                    admins: state.admins,
                    users: state.users
                },
                null,
                2
            ),
            "utf8"
        );
    } catch (e) {
        console.error("Error saving users.json:", e);
    }
}

load();

// ----- Helpers -----
function generateId(prefix) {
    return (
        prefix +
        "_" +
        Math.random().toString(36).slice(2) +
        Date.now().toString(36)
    );
}

function normalizeTelegramUsername(value) {
    if (!value) return "";
    return String(value).trim().replace(/^@+/, "").toLowerCase();
}

// ----- Admin -----
function getAdmins() {
    return state.admins;
}

function addAdmin({ username, passwordHash, phone, telegramUsername }) {
    const normalizedTelegram = normalizeTelegramUsername(telegramUsername);
    if (!normalizedTelegram) {
        throw new Error("telegramUsername is required");
    }
    if (state.admins.some((a) => normalizeTelegramUsername(a.telegramUsername) === normalizedTelegram)) {
        throw new Error("An admin with this Telegram username already exists");
    }

    const admin = {
        id: generateId("adm"),
        username,
        passwordHash,
        phone,
        telegramUsername: normalizedTelegram,
        telegramChatId: null,
        enabled: true,
        sessionId: null // per la singola sessione attiva
    };

    state.admins.push(admin);
    save();
    return admin;
}

function findAdminByUsername(username) {
    return state.admins.find((a) => a.username === username);
}

function findAdminById(id) {
    return state.admins.find((a) => a.id === id);
}
function setAdminSession(adminId, sessionId) {
    const admin = findAdminById(adminId);
    if (!admin) return false;
    admin.sessionId = sessionId;
    save();
    return true;
}
function findAdminByTelegramUsername(username) {
    const normalized = normalizeTelegramUsername(username);
    if (!normalized) return null;
    return state.admins.find((a) => normalizeTelegramUsername(a.telegramUsername) === normalized) || null;
}
function setAdminTelegramChatId(adminId, chatId) {
    const admin = findAdminById(adminId);
    if (!admin) return false;
    admin.telegramChatId = chatId;
    save();
    return true;
}

// ----- Utenti normali -----
function getUsers() {
    return state.users;
}

function deleteUser(id) {
    const before = state.users.length;
    state.users = state.users.filter(u => u.id !== id);
    if (state.users.length === before) return false;
    save();        // la tua funzione che scrive data/users.json
    return true;
}

function addUser({ username, telegramUsername, telegramChatId = null, enabled = true, faceRegistered = false }) {
    const normalizedTelegram = normalizeTelegramUsername(telegramUsername);
    if (!username || !normalizedTelegram) {
        throw new Error("username and telegramUsername are required");
    }

    // univoco per telegramUsername
    const existsTelegram =
        state.users.some(u => normalizeTelegramUsername(u.telegramUsername) === normalizedTelegram) ||
        state.admins.some(a => normalizeTelegramUsername(a.telegramUsername) === normalizedTelegram);

    if (existsTelegram) {
        throw new Error("A user or admin with this Telegram username already exists");
    }

    const user = {
        id: generateId("usr"),
        username,
        telegramUsername: normalizedTelegram,
        telegramChatId,
        enabled: !!enabled,
        faceRegistered: !!faceRegistered
    };

    state.users.push(user);
    save();
    return user;
}
function getUserById(id) {
    return state.users.find(u => u.id === id) || null;
}

function findUserByTelegramUsername(telegramUsername) {
    const normalized = normalizeTelegramUsername(telegramUsername);
    if (!normalized) return null;
    return state.users.find(
        u => normalizeTelegramUsername(u.telegramUsername) === normalized
    ) || null;
}


function setUserEnabled(userId, enabled) {
    const user = state.users.find((u) => u.id === userId);
    if (!user) return null;
    user.enabled = !!enabled;
    save();
    return user;
}

function isUserChat(chatId) {
    return state.users.some(u => u.telegramChatId === chatId);
}

function getUserByChatId(chatId) {
    return state.users.find(u => u.telegramChatId === chatId) || null;
}
// Collega una chat Telegram a un admin o utente, cercando per username Telegram
function linkTelegramChat(telegramUsername, chatId) {
    const normalized = normalizeTelegramUsername(telegramUsername);
    if (!normalized) return null;

    // admin (nel tuo caso ce n'è solo uno, ma gestiamo lista per sicurezza)
    let admin = state.admins.find(a => normalizeTelegramUsername(a.telegramUsername) === normalized);
    if (admin) {
        admin.telegramChatId = chatId;
        save();
        return { ...admin, role: "admin" };
    }

    // utente normale
    let user = state.users.find(u => normalizeTelegramUsername(u.telegramUsername) === normalized);
    if (user) {
        user.telegramChatId = chatId;
        user.enabled = true;
        save();
        return { ...user, role: "user" };
    }

    return null;
}

// vero se questa chat appartiene a un admin abilitato
function isAdminChat(chatId) {
    return state.admins.some(a => a.telegramChatId === chatId && a.enabled);
}

// siccome hai deciso di avere UN solo admin, prendiamo il primo
function getSingleAdmin() {
    return state.admins[0] || null;
}

// ----- Export -----
module.exports = {
    getAdmins,
    getUsers,
    addAdmin,
    addUser,
    deleteUser,
    findAdminByUsername,
    findAdminByTelegramUsername,
    findUserByTelegramUsername,
    findAdminById,
    setAdminSession,
    setUserEnabled,
    normalizeTelegramUsername,
    linkTelegramChat,
    isAdminChat,
    getSingleAdmin,
    isUserChat,
    getUserByChatId,
    getUserById
};
