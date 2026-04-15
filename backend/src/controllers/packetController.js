const PacketLog = require("../models/PacketLog");

const getPackets = async (req, res) => {
  try {
    const packets = await PacketLog.find().sort({ timestamp: -1 });
    res.status(200).json(packets);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch packet logs" });
  }
};

const getAlerts = async (req, res) => {
  try {
    const alerts = await PacketLog.find({ alert: true }).sort({ timestamp: -1 });
    res.status(200).json(alerts);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch alerts" });
  }
};

const getStats = async (req, res) => {
  try {
    const protocolStats = await PacketLog.aggregate([
      {
        $group: {
          _id: "$protocol",
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          _id: 0,
          protocol: "$_id",
          count: 1
        }
      },
      {
        $sort: {
          protocol: 1
        }
      }
    ]);

    res.status(200).json(protocolStats);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch packet stats" });
  }
};

module.exports = {
  getPackets,
  getAlerts,
  getStats
};
