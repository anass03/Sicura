// routes/accessRoutes.js
const express = require("express");
const { requireAdmin } = require("../middleware/authMiddleware");
const accessService = require("../services/accessService");
const userStore = require("../services/userStore");

const router = express.Router();

// GET /api/status  (solo admin loggato)
router.get("/status", requireAdmin, (req, res) => {
    res.json(accessService.getStatus());
});

// POST /api/decision  (solo admin)
router.post("/decision", requireAdmin, (req, res) => {
    const { decision } = req.body;
    if (decision !== "OK" && decision !== "KO") {
        return res
            .status(400)
            .json({ error: "decision must be OK or KO" });
    }
    const status = accessService.getStatus();
    if (
        status.currentRequest &&
        status.currentRequest.registered &&
        status.currentRequest.enabled !== false
    ) {
        // richiesta di utente registrato -> deve gestirla lui da Telegram
        return res.status(400).json({
            error:
                "Requests from registered users must be handled via Telegram."
        });
    }
    accessService.handleDecision(decision, "web");
    res.json({ ok: true });
});

// Rigenera OTP condiviso (solo admin)
router.post("/otp/regenerate", requireAdmin, (req, res) => {
    try {
        const info = accessService.regenerateOtp?.("manual");
        res.json({ ok: true, otp: info?.otp || null, updatedAt: info?.updatedAt || null });
    } catch (e) {
        res.status(500).json({ error: e.message || "Unable to regenerate OTP" });
    }
});

// ====== GESTIONE UTENTI (solo admin) ======

// lista utenti
router.get("/users", requireAdmin, (req, res) => {
    res.json({ users: userStore.getUsers() });
});

// FASE 1: avvio registrazione (NON crea ancora l'utente nel userStore)
router.post("/users", requireAdmin, (req, res) => {
    const { username, telegramUsername } = req.body;

    if (!username || !telegramUsername) {
        return res
            .status(400)
            .json({ error: "username and telegramUsername are required" });
    }

    const normalizedTelegram = userStore.normalizeTelegramUsername(telegramUsername);
    if (!normalizedTelegram) {
        return res.status(400).json({ error: "telegramUsername is required" });
    }

    // Prevent duplicates: Telegram usernames must be unique (case-insensitive, without @)
    const existsUser = !!userStore.findUserByTelegramUsername(normalizedTelegram);
    const existsAdmin = !!userStore.findAdminByTelegramUsername?.(normalizedTelegram);
    if (existsUser || existsAdmin) {
        return res.status(409).json({ error: "Telegram username already exists" });
    }

    // Also prevent duplicates with an already-started (active) pending registration
    const pending = accessService.getPendingUsers();
    const hasSameTelegramPending = pending.some(
        (p) =>
            p &&
            p.status !== "DONE" &&
            p.status !== "FAILED" &&
            userStore.normalizeTelegramUsername(p.telegramUsername) === normalizedTelegram
    );
    if (hasSameTelegramPending) {
        return res.status(409).json({ error: "A registration for this Telegram username is already in progress" });
    }

    const hasActivePending = pending.some(
        (p) => p.status !== "DONE" && p.status !== "FAILED"
    );
    if (hasActivePending) {
        return res.status(400).json({
            error: "A registration is already in progress. Please complete it before starting another one."
        });
    }

    try {
        // NON chiamo userStore.addUser qui
        const tempUser = { username, telegramUsername: normalizedTelegram };

        accessService.notifyUserUpdateToArduino("START_ENROLL", tempUser);

        res.json({
            ok: true,
            message:
                "Registration started. The user will not be created until face enrollment is completed and they send /start to the Telegram bot."
        });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});


// abilita / disabilita utente
router.patch("/users/:id", requireAdmin, (req, res) => {
    const { enabled } = req.body;

    if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled must be a boolean" });
    }

    // assumiamo che setUserEnabled ritorni l'utente aggiornato oppure null/undefined se non trovato
    const user = userStore.setUserEnabled(req.params.id, enabled);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    res.json({ ok: true });
});

// elimina utente
router.delete("/users/:id", requireAdmin, (req, res) => {
    const user = userStore.getUserById(req.params.id);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    try {
        const started = accessService.requestDeleteUser(user);
        if (!started) {
            return res.status(409).json({ error: "A deletion is already in progress for this user" });
        }

        // 202 = richiesta accettata ma non completata
        return res.status(202).json({ ok: true, pending: true });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});


router.get("/pending", requireAdmin, (req, res) => {
    res.json({ pending: accessService.getPendingUsers() });
});
router.get("/pending-deletes", requireAdmin, (req, res) => {
    res.json({ pending: accessService.getPendingDeletes() });
});

module.exports = router;
