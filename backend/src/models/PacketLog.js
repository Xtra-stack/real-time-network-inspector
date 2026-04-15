const mongoose = require("mongoose");

const packetLogSchema = new mongoose.Schema(
  {
    sourceIp: {
      type: String,
      required: true
    },
    destinationIp: {
      type: String,
      required: true
    },
    protocol: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      required: true
    },
    alert: {
      type: Boolean,
      default: false
    }
  },
  {
    versionKey: false
  }
);

module.exports = mongoose.model("PacketLog", packetLogSchema);
