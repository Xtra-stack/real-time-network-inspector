const path = require("path");
const { spawn } = require("child_process");
const readline = require("readline");
const { analyzePacket } = require("./packetAnalyzer");
const PacketLog = require("../models/PacketLog");

const startSnifferService = () => {
  const defaultCommand = path.resolve(__dirname, "../../../cpp-sniffer/sniffer");
  const snifferCommand = process.env.SNIFFER_COMMAND || defaultCommand;
  const snifferInterface = process.env.SNIFFER_INTERFACE || "eth0";

  const snifferProcess = spawn(snifferCommand, [snifferInterface]);

  const lineReader = readline.createInterface({
    input: snifferProcess.stdout,
    crlfDelay: Infinity
  });

  lineReader.on("line", (line) => {
    if (!line.trim()) {
      return;
    }

    try {
      const packet = JSON.parse(line);
      const analyzedPacket = analyzePacket(packet);
      console.log("Analyzed packet:", analyzedPacket);

      PacketLog.create({
        sourceIp: analyzedPacket.sourceIp,
        destinationIp: analyzedPacket.destinationIp,
        protocol: analyzedPacket.protocolType,
        timestamp: new Date(analyzedPacket.timestamp),
        alert: analyzedPacket.alert
      }).catch((error) => {
        console.error("Could not save packet log:", error.message);
      });
    } catch (error) {
      console.error("Could not parse packet JSON:", line);
    }
  });

  snifferProcess.stderr.on("data", (chunk) => {
    console.error("Sniffer error:", chunk.toString().trim());
  });

  snifferProcess.on("error", (error) => {
    console.error("Failed to start sniffer process:", error.message);
  });

  snifferProcess.on("close", (code) => {
    console.log(`Sniffer process stopped with code ${code}`);
  });

  return snifferProcess;
};

module.exports = {
  startSnifferService
};
