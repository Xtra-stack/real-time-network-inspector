const mongoose = require("mongoose");
const mixed = mongoose.Schema.Types.Mixed;

const packetLogSchema = new mongoose.Schema(
  {
    packetNumber: { type: Number, required: true },
    captureId: { type: String, required: true },
    timestamp: {
      type: Date,
      required: true
    },
    captureLength: Number,
    originalLength: Number,
    linkType: Number,
    ethernet: mixed,
    ip: mixed,
    tcp: mixed,
    udp: mixed,
    icmp: mixed,
    arp: mixed,
    dns: mixed,
    dhcp: mixed,
    tls: mixed,
    http: mixed,
    ssh: mixed,
    ftp: mixed,
    smtp: mixed,
    raw: mixed,
    payload: mixed,
    protocol: { type: String, required: true },
    info: String,
    decodeStatus: String,
    rawStatus: String,
    rawUnavailableReason: String
  },
  {
    versionKey: false
  }
);

module.exports = mongoose.model("PacketLog", packetLogSchema);
