const express = require("express");
const { getHealth } = require("../controllers/healthController");
const {
	getPackets,
	getAlerts,
	getStats
} = require("../controllers/packetController");

const router = express.Router();

router.get("/health", getHealth);
router.get("/packets", getPackets);
router.get("/alerts", getAlerts);
router.get("/stats", getStats);

module.exports = router;
