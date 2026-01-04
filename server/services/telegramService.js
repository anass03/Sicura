// services/telegramService.js
const TelegramBot = require("node-telegram-bot-api");
const { TELEGRAM_TOKEN } = require("../config");
const accessService = require("./accessService");
const userStore = require("./userStore");

// se non hai messo il token, non attiviamo il bot
if (!TELEGRAM_TOKEN) {
    console.warn("⚠️ No TELEGRAM_TOKEN configured. Telegram bot disabled.");
    module.exports = {
        notifyAccessRequest: () => {},
        notifyUserRegistered: () => {},
        notifyOtpForUser: () => {},
        notifyOtpChanged: () => {},
    };
    return;
}

const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

bot.on("polling_error", (err) => {
    console.error("Telegram polling error:", err && err.code, err && err.response && err.response.body);
});

bot.on("message", (msg) => {
    console.log("Telegram message from", msg.from.username, "chat", msg.chat.id);
});

// /start: collega la chat all'admin (o utente) corrispondente all'username Telegram
bot.onText(/\/start/, async (msg) => {
    try {
        const username = userStore.normalizeTelegramUsername(msg.from.username);      // es: "anass003"
        const chatId = msg.chat.id;

        console.log("Comando /start da", username, "chat", chatId);

        if (!username) {
            await bot.sendMessage(
                chatId,
                "I can't read your Telegram username. Please set one in Telegram settings and try again."
            );
            return;
        }

        // 👇 NUOVO: prima proviamo a usarlo per la procedura 2-fasi
        const status = accessService.notifyTelegramStart(username, chatId);

        if (status === "FINALIZED") {
            // await bot.sendMessage(
            //     chatId,
            //     "✅ Registration completed.\nYou will now receive notifications and can approve access requests."
            // );
            return;
        }

        if (status === "WAIT_FACE") {
            await bot.sendMessage(
                chatId,
                "Your Telegram has been linked. Please complete face enrollment on the device to finish registration."
            );
            return;
        }

        // 👉 NO_PENDING: comportamento vecchio
        const linked = userStore.linkTelegramChat(username, chatId);

        if (!linked) {
            await bot.sendMessage(
                chatId,
                "You are not registered in the system. Please contact an administrator."
            );
            return;
        }

        await bot.sendMessage(
            chatId,
            "Hi! I'm the access control bot.\n" +
            "I'll use this chat for notifications and approvals."
        );
    } catch (err) {
        console.error("Error in /start handler:", err);
    }
});

// /si e /no usati dall'ADMIN per confermare o negare
async function handleYes(msg) {
    try {
        const chatId = msg.chat.id;

        const isAdmin = userStore.isAdminChat(chatId);
        const isUser  = userStore.isUserChat(chatId);

        if (!isAdmin && !isUser) {
            return;
        }

        // 🔹 Nessuna richiesta in corso → esci subito
        if (!accessService.hasPendingRequest()) {
            return;
        }

        await accessService.handleDecision("OK", "telegram");

        if (isAdmin) {
            await bot.sendMessage(
                chatId,
                `✅ You approved access for ${msg.from.username}.`
            );
        } else {
            await bot.sendMessage(chatId, "✅ You approved your access request.");
        }
    } catch (err) {
        console.error("Error in /yes:", err);
    }
}

// Backward-compatible: /si, preferred: /yes
bot.onText(/\/si/, handleYes);
bot.onText(/\/yes/, handleYes);

async function handleNo(msg) {
    try {
        const chatId = msg.chat.id;

        const isAdmin = userStore.isAdminChat(chatId);
        const isUser  = userStore.isUserChat(chatId);

        if (!isAdmin && !isUser) {
            return;
        }

        // 🔹 Nessuna richiesta in corso → esci subito
        if (!accessService.hasPendingRequest()) {
            return;
        }

        await accessService.handleDecision("KO", "telegram");
        if (isAdmin) {
            await bot.sendMessage(
                chatId,
                `⛔ You denied access for ${msg.from.username}.`
            );
        } else {
            await bot.sendMessage(chatId, "⛔ You denied your access request.");
        }
    } catch (err) {
        console.error("Error in /no:", err);
    }
}

bot.onText(/\/no/, handleNo);


function notifyAccessRequest(request) {

    // 👮‍♂️ CASO: utente DISABILITATO → solo admin
    if (request.enabled === false) {
        return notifyAdmin(
            "⛔ *Access request from a DISABLED user*\n" +
            `👤 User: *${request.telegramUsername}*\n\n` +
            "Reply with /yes to APPROVE or /no to DENY."
        );
    }

    // 👤 CASO: utente registrato e abilitato → solo lui
    if (request.registered && request.telegramUsername) {
        const user = userStore.findUserByTelegramUsername(request.telegramUsername);
        if (user?.telegramChatId) {
            const text =
                "🔐 New access request\n\n" +
                `👤 User: *${request.telegramUsername}*\n\n` +
                "Reply with /yes to APPROVE or /no to DENY.";

            bot.sendMessage(user.telegramChatId, text, { parse_mode: "Markdown" });
            return;
        }
    }

    // 👮‍♂️ CASO: non registrato / senza chat → admin
    notifyAdmin(
        "🔐 *Access request from an UNREGISTERED user*\n" +
        `👤 User: *${request.telegramUsername}*\n\n` +
        "Reply with /yes to APPROVE or /no to DENY."
    );
}

function notifyAdmin(text) {
    const admin = userStore.getSingleAdmin();
    if (!admin?.telegramChatId) return;
    bot.sendMessage(admin.telegramChatId, text, { parse_mode: "Markdown" });
}

// messaggino quando registri un utente/admin
function notifyUserRegistered(user) {
    if (!user.telegramChatId) return;

    // admin se l'id inizia con "adm_", utente normale se "usr_"
    const isAdmin = typeof user.id === "string" && user.id.startsWith("adm_");

    const text = isAdmin
        ? "You have been registered successfully as an admin for the access control system."
        : "You have been registered successfully.";

    bot.sendMessage(user.telegramChatId, text);
}

async function notifyOtpForUser(user, otpInfo, reason = "registration") {
    if (!user?.telegramChatId || !otpInfo?.otp) return;
    const when = otpInfo.updatedAt ? `\nUpdated at: ${otpInfo.updatedAt}` : "";
    const prefix = reason === "registration"
        ? "Here is your access OTP."
        : "Access OTP update.";
    const text = `${prefix}\n\nOTP: *${otpInfo.otp}*${when}\nPlease keep it safe.`;
    try {
        await bot.sendMessage(user.telegramChatId, text, { parse_mode: "Markdown" });
    } catch (err) {
        console.error("Error sending OTP to user", user.telegramUsername, err);
    }
}

async function notifyOtpChanged(otpInfo) {
    if (!otpInfo?.otp) return;

    const recipients = [...userStore.getAdmins(), ...userStore.getUsers()]
        .filter((u) => u?.telegramChatId);
    const seen = new Set();
    const text = `🔐 The shared OTP has been updated.\n\nNew OTP: *${otpInfo.otp}*\nUpdated at: ${otpInfo.updatedAt || "now"}`;

    for (const rec of recipients) {
        if (seen.has(rec.telegramChatId)) continue;
        seen.add(rec.telegramChatId);
        try {
            await bot.sendMessage(rec.telegramChatId, text, { parse_mode: "Markdown" });
        } catch (err) {
            console.error("Error notifying OTP change to", rec.telegramUsername, err);
        }
    }
}


module.exports = {
    notifyAccessRequest,
    notifyUserRegistered,
    notifyOtpForUser,
    notifyOtpChanged,
};
