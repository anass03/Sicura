const express = require("express");
const { requireAdmin } = require("../middleware/authMiddleware");
const { RYU_API_BASE } = require("../config");

const router = express.Router();

const MGMT_DEFAULT = "http://10.0.0.1:8080";
const LOCAL_PROXY = "http://127.0.0.1:18080";
const LOCAL_DIRECT = "http://localhost:8080";

const fallbacks = [];
if (RYU_API_BASE && ![MGMT_DEFAULT, LOCAL_PROXY].includes(RYU_API_BASE))
    fallbacks.push(RYU_API_BASE);
fallbacks.push(LOCAL_PROXY);
fallbacks.push(LOCAL_DIRECT);
fallbacks.push(MGMT_DEFAULT);

async function forwardJson(res, targetPath, options = {}) {
    const errors = [];
    for (const base of fallbacks) {
        const url = `${base}${targetPath}`;
        try {
            const controllerRes = await fetch(url, {
                ...options,
                headers: {
                    "Content-Type": "application/json",
                    ...(options.headers || {}),
                },
            });
            const text = await controllerRes.text();
            let payload = text;
            try {
                payload = text ? JSON.parse(text) : {};
            } catch (e) {
                // leave payload as text
            }
            if (!controllerRes.ok) {
                return res.status(controllerRes.status).json({
                    error: "Ryu controller error",
                    details: payload,
                    target: url,
                });
            }
            console.info(
                `[firewall-proxy] ${options.method || "GET"} ${targetPath} via ${base}`,
            );
            return res.status(controllerRes.status).json(payload);
        } catch (err) {
            errors.push({ base, message: err.message });
            continue;
        }
    }
    return res.status(502).json({
        error: "Unable to reach Ryu controller",
        tried: errors,
    });
}

router.get("/status", requireAdmin, async (req, res) => {
    return forwardJson(res, "/api/firewall/status", { method: "GET" });
});

router.get("/events", requireAdmin, async (req, res) => {
    const limit = req.query?.limit ? Number(req.query.limit) : 200;
    const query = isNaN(limit) ? "" : `?limit=${limit}`;
    return forwardJson(res, `/api/firewall/events${query}`, { method: "GET" });
});

router.post("/block", requireAdmin, async (req, res) => {
    return forwardJson(res, "/api/firewall/block", {
        method: "POST",
        body: JSON.stringify(req.body || {}),
    });
});

router.post("/unblock", requireAdmin, async (req, res) => {
    return forwardJson(res, "/api/firewall/unblock", {
        method: "POST",
        body: JSON.stringify(req.body || {}),
    });
});

router.post("/block_port", requireAdmin, async (req, res) => {
    return forwardJson(res, "/api/firewall/block_port", {
        method: "POST",
        body: JSON.stringify(req.body || {}),
    });
});

router.post("/unblock_port", requireAdmin, async (req, res) => {
    return forwardJson(res, "/api/firewall/unblock_port", {
        method: "POST",
        body: JSON.stringify(req.body || {}),
    });
});

module.exports = router;
