const PacketLog = require("../models/PacketLog");
const { parseCaptureRecord } = require("../services/packetParser");

const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const buildPacketListQuery = (query = {}) => {
  const filter = {};
  const protocol = typeof query.protocol === "string" ? query.protocol.trim() : "";
  const captureId = typeof query.captureId === "string" ? query.captureId.trim() : "";
  const q = typeof query.q === "string" ? query.q.trim() : "";

  if (protocol) {
    filter.protocol = new RegExp(`^${escapeRegex(protocol)}$`, "i");
  }

  if (captureId) {
    filter.captureId = captureId;
  }

  if (!q) return filter;

  const numericQuery = Number(q);
  const searchPattern = new RegExp(escapeRegex(q), "i");
  const searchMatch = {
    $or: [
      { packetNumber: Number.isInteger(numericQuery) ? numericQuery : -1 },
      { protocol: searchPattern },
      { info: searchPattern },
      { captureId: searchPattern },
      { source: searchPattern },
      { destination: searchPattern },
      { "ip.source": searchPattern },
      { "ip.destination": searchPattern },
      { "tcp.sourcePort": Number.isInteger(numericQuery) ? numericQuery : -1 },
      { "tcp.destinationPort": Number.isInteger(numericQuery) ? numericQuery : -1 },
      { "udp.sourcePort": Number.isInteger(numericQuery) ? numericQuery : -1 },
      { "udp.destinationPort": Number.isInteger(numericQuery) ? numericQuery : -1 }
    ]
  };

  if (!filter.$or) {
    filter.$or = searchMatch.$or;
    return filter;
  }

  filter.$and = [{ $or: searchMatch.$or }];
  return filter;
};

const parsePacketListOptions = (query = {}) => {
  const page = Number.parseInt(query.page ?? "1", 10);
  const limit = Number.parseInt(query.limit ?? "50", 10);
  return {
    page: Number.isFinite(page) && page > 0 ? page : 1,
    limit: Number.isFinite(limit) && limit > 0 ? Math.min(limit, 500) : 50
  };
};

const normalizeStoredPacket = (document, { includeRaw = true } = {}) => {
  const packet = { ...document };
  delete packet._id;
  delete packet.__v;

  if (!includeRaw && packet.raw?.bytes &&
      (packet.ip || packet.ethernet || packet.tcp || packet.udp || packet.icmp || packet.arp)) {
    packet.rawStatus = "AVAILABLE";
    delete packet.raw;
    delete packet.payload;
    return packet;
  }

  if (packet.raw?.bytes && Number.isInteger(packet.captureLength) &&
      Number.isInteger(packet.originalLength) && Number.isInteger(packet.linkType)) {
    try {
      const normalizedPacket = {
        ...parseCaptureRecord({
          timestamp: packet.timestamp,
          captureLength: packet.captureLength,
          originalLength: packet.originalLength,
          linkType: packet.linkType,
          bytes: packet.raw.bytes
        }, packet.packetNumber),
        captureId: packet.captureId
      };
      if (!includeRaw) {
        delete normalizedPacket.raw;
        delete normalizedPacket.payload;
      }
      return normalizedPacket;
    } catch (_error) {
      return {
        packetNumber: packet.packetNumber,
        timestamp: packet.timestamp,
        captureLength: packet.captureLength,
        originalLength: packet.originalLength,
        linkType: packet.linkType,
        protocol: "UNKNOWN",
        info: "Stored frame failed capture-record validation.",
        decodeStatus: "invalid-capture-record",
        raw: null,
        payload: null,
        captureId: packet.captureId
      };
    }
  }

  if (packet.ip || packet.ethernet || packet.raw) {
    if (!packet.raw?.bytes) {
      packet.rawStatus = packet.rawStatus || "RAW_BYTES_UNAVAILABLE";
      packet.rawUnavailableReason = packet.rawUnavailableReason ||
        "Capture source did not provide the original frame bytes.";
    }
    return packet;
  }

  const legacyPacket = {
    packetNumber: packet.packetNumber,
    timestamp: packet.timestamp,
    captureLength: packet.capturedLength ?? null,
    originalLength: packet.originalLength ?? packet.packetLength ?? null,
    captureId: packet.captureId ?? null,
    protocol: packet.protocol || "UNKNOWN",
    info: "Legacy summary only; original frame bytes were not stored.",
    decodeStatus: "legacy-summary",
    rawStatus: "RAW_BYTES_UNAVAILABLE",
    rawUnavailableReason: "This historical record predates raw frame storage.",
    raw: null,
    payload: null
  };

  if (packet.sourceIp || packet.destinationIp) {
    legacyPacket.ip = {
      version: 4,
      source: packet.sourceIp,
      destination: packet.destinationIp
    };
  }
  if (packet.sourcePort !== undefined || packet.destinationPort !== undefined) {
    legacyPacket.tcp = packet.tcpFlags ? {
      sourcePort: packet.sourcePort,
      destinationPort: packet.destinationPort,
      sequenceNumber: packet.tcpSequenceNumber,
      acknowledgementNumber: packet.tcpAcknowledgementNumber,
      flags: packet.tcpFlags
    } : undefined;
    legacyPacket.udp = packet.udpLength ? {
      sourcePort: packet.sourcePort,
      destinationPort: packet.destinationPort,
      length: packet.udpLength
    } : undefined;
  }
  return legacyPacket;
};

const createPacketSummary = (packet) => {
  const summary = { ...packet };
  const hasRawBytes = typeof summary.raw?.bytes === "string" && summary.raw.bytes.length > 0;
  summary.rawStatus = hasRawBytes ? "AVAILABLE" : summary.rawStatus || "RAW_BYTES_UNAVAILABLE";
  if (!hasRawBytes && !summary.rawUnavailableReason) {
    summary.rawUnavailableReason = "Capture source did not provide the original frame bytes.";
  }
  delete summary.raw;
  delete summary.payload;
  return summary;
};

const getPackets = async (req, res) => {
  try {
    const query = buildPacketListQuery(req.query || {});
    const { page, limit } = parsePacketListOptions(req.query || {});
    const hasPagingOrFilter = Object.keys(req.query || {}).length > 0;
    const total = await PacketLog.countDocuments(query);
    const packets = await PacketLog.find(query)
      .sort({ timestamp: -1, packetNumber: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const normalizedPackets = packets.map((packet) =>
      createPacketSummary(normalizeStoredPacket(packet, { includeRaw: false }))
    );

    if (hasPagingOrFilter) {
      return res.status(200).json({
        packets: normalizedPackets,
        total,
        page,
        pageSize: limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
        hasMore: page * limit < total
      });
    }

    return res.status(200).json(normalizedPackets);
  } catch (error) {
    return res.status(500).json({ message: "Failed to fetch packet logs" });
  }
};

const getPacketDetails = async (req, res) => {
  const packetNumber = Number(req.params.packetNumber);
  const captureId = req.params.captureId;
  if (!captureId || !Number.isInteger(packetNumber) || packetNumber < 1) {
    return res.status(400).json({ message: "Invalid packet reference" });
  }

  try {
    const packet = await PacketLog.findOne({ captureId, packetNumber }).lean();
    if (!packet) return res.status(404).json({ message: "Packet details are not available" });
    return res.status(200).json(normalizeStoredPacket(packet));
  } catch (_error) {
    return res.status(500).json({ message: "Failed to fetch packet details" });
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
  getPacketDetails,
  getAlerts,
  getStats,
  buildPacketListQuery,
  parsePacketListOptions,
  normalizeStoredPacket,
  createPacketSummary
};
