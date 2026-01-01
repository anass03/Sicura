const express = require("express");
const router = express.Router();
const { requireAdmin } = require("../middleware/authMiddleware");
const labManager = require("../services/labManager");

router.post("/start", requireAdmin, (req, res) => {
  const result = labManager.startLab();
  if (!result.ok && result.error === "busy") return res.status(409).json(result);
  if (!result.ok) return res.status(500).json(result);
  return res.json(result);
});

router.post("/stop", requireAdmin, (req, res) => {
  const result = labManager.stopLab();
  if (!result.ok && result.error === "busy") return res.status(409).json(result);
  if (!result.ok) return res.status(500).json(result);
  return res.json(result);
});

module.exports = router;
