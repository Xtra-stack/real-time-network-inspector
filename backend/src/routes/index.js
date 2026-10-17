const express = require("express");
const { getHealth } = require("../controllers/healthController");
const {
	getPackets,
	getPacketDetails,
	getAlerts,
	getStats
} = require("../controllers/packetController");
const { getSharedSnifferService } = require("../services/sniffer");

const router = express.Router();

const getSnifferService = () => {
  const service = getSharedSnifferService();
  if (!service) {
    return null;
  }
  return service;
};

router.get("/health", getHealth);
router.get("/packets", getPackets);
router.get("/packets/:captureId/:packetNumber", getPacketDetails);
router.get("/alerts", getAlerts);
router.get("/stats", getStats);

router.get("/capture/interfaces", async (_req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  try {
    const interfaces = await service.listInterfaces();
    if (!interfaces.length && service.getStatus().lastError) {
      return res.status(503).json({ message: service.getStatus().lastError, interfaces: [] });
    }
    return res.status(200).json(interfaces);
  } catch (error) {
    return res.status(500).json({ message: error.message || "Failed to list network interfaces." });
  }
});

router.get("/capture/status", (_req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  return res.status(200).json(service.getStatus());
});

router.post("/capture/start", async (req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  try {
    const result = await service.start({ interfaceName: req.body?.interfaceName });
    if (!result.ok) {
      return res.status(400).json({ message: result.error || "Unable to start capture." });
    }
    return res.status(200).json({ ...result, status: service.getStatus().status });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Failed to start the capture process." });
  }
});

router.post("/capture/pause", (_req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  const result = service.pause();
  if (!result.ok) {
    return res.status(400).json({ message: result.error || "Unable to pause capture." });
  }
  return res.status(200).json({ ...result, status: service.getStatus().status });
});

router.post("/capture/resume", (_req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  const result = service.resume();
  if (!result.ok) {
    return res.status(400).json({ message: result.error || "Unable to resume capture." });
  }
  return res.status(200).json({ ...result, status: service.getStatus().status });
});

router.post("/capture/stop", async (_req, res) => {
  const service = getSnifferService();
  if (!service) {
    return res.status(503).json({ message: "Capture service is not initialized." });
  }

  const result = await service.stop();
  if (!result.ok) {
    return res.status(400).json({ message: result.error || "Unable to stop capture." });
  }
  return res.status(200).json({ ...result, status: service.getStatus().status });
});

module.exports = router;
