const MAX_TRACKED_FLOWS = 5000;
const HANDSHAKE_TIMEOUT_MS = 3000;

const getFlowKey = (packet) => [
  packet.ip.source,
  packet.tcp.sourcePort,
  packet.ip.destination,
  packet.tcp.destinationPort
].join("|");

const getReverseFlowKey = (packet) => [
  packet.ip.destination,
  packet.tcp.destinationPort,
  packet.ip.source,
  packet.tcp.sourcePort
].join("|");

const getSeverity = (score) => {
  if (score >= 90) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
};

const createInvestigationAnalyzer = () => {
  const flows = new Map();
  let capturedPackets = 0;
  let decodedTcpPackets = 0;

  const getOrCreateFlow = (packet) => {
    const key = getFlowKey(packet);
    let flow = flows.get(key);

    if (!flow) {
      if (flows.size >= MAX_TRACKED_FLOWS) {
        const oldestKey = flows.keys().next().value;
        flows.delete(oldestKey);
      }

      flow = {
        key,
        sourceIp: packet.ip.source,
        sourcePort: packet.tcp.sourcePort,
        destinationIp: packet.ip.destination,
        destinationPort: packet.tcp.destinationPort,
        synAttempts: []
      };
      flows.set(key, flow);
    }

    return flow;
  };

  const ingest = (packet) => {
    capturedPackets += 1;
    if (!packet.tcp || !packet.ip?.source || !packet.ip?.destination) {
      return;
    }

    decodedTcpPackets += 1;
    const flags = packet.tcp.flags;

    if (flags.syn && !flags.ack) {
      const flow = getOrCreateFlow(packet);
      flow.synAttempts.push({
        packetNumber: packet.packetNumber,
        timestamp: packet.timestamp,
        sequenceNumber: packet.tcp.sequenceNumber
      });
      if (flow.synAttempts.length > 100) {
        flow.synAttempts.shift();
      }
    }

    if (flags.syn && flags.ack) {
      const attemptedFlow = flows.get(getReverseFlowKey(packet));
      if (attemptedFlow) {
        const matchedAttempts = attemptedFlow.synAttempts.filter((attempt) => {
          if (!Number.isInteger(attempt.sequenceNumber) || !Number.isInteger(packet.tcp.acknowledgementNumber)) {
            return true;
          }
          return ((attempt.sequenceNumber + 1) >>> 0) === packet.tcp.acknowledgementNumber;
        });

        for (const attempt of matchedAttempts) {
          attempt.synAckPacketNumber = packet.packetNumber;
        }
      }
    }

  };

  const getFindings = (now = Date.now()) => {
    const failuresByTarget = new Map();

    for (const flow of flows.values()) {
      const failedAttempts = flow.synAttempts.filter((attempt) => {
        if (attempt.synAckPacketNumber) return false;
        const age = now - Date.parse(attempt.timestamp);
        return Number.isFinite(age) && age >= HANDSHAKE_TIMEOUT_MS;
      });

      if (!failedAttempts.length) continue;

      const targetKey = `${flow.destinationIp}:${flow.destinationPort}`;
      let target = failuresByTarget.get(targetKey);
      if (!target) {
        target = {
          destinationIp: flow.destinationIp,
          destinationPort: flow.destinationPort,
          sourceEndpoints: new Set(),
          sourceHosts: new Set(),
          flowKeys: new Set(),
          evidence: []
        };
        failuresByTarget.set(targetKey, target);
      }

      target.sourceEndpoints.add(`${flow.sourceIp}:${flow.sourcePort}`);
      target.sourceHosts.add(flow.sourceIp);
      target.flowKeys.add(flow.key);
      target.evidence.push(...failedAttempts);
    }

    return [...failuresByTarget.values()]
      .map((target) => {
        const packetNumbers = [...new Set(target.evidence.map((item) => item.packetNumber))]
          .filter(Number.isInteger)
          .sort((left, right) => left - right);
        const packetCount = packetNumbers.length;
        const flowCount = target.flowKeys.size;
        const hostCount = target.sourceHosts.size;
        const score = Math.min(
          100,
          20 + Math.max(0, packetCount - 1) * 4 + Math.max(0, flowCount - 1) * 8 + Math.max(0, hostCount - 1) * 4
        );
        const sources = [...target.sourceEndpoints].sort();
        const sourceHosts = [...target.sourceHosts].sort();
        const earliest = target.evidence
          .map((item) => Date.parse(item.timestamp))
          .filter(Number.isFinite)
          .sort((left, right) => left - right)[0];

        return {
          id: `tcp-handshake:${target.destinationIp}:${target.destinationPort}`,
          priority: getSeverity(score),
          severity: getSeverity(score),
          priorityScore: score,
          title: "Possible TCP connection failure",
          confidence: packetCount > 1 ? "medium" : "low",
          source: sources.length === 1 ? sources[0] : `${hostCount} source hosts`,
          destination: `${target.destinationIp}:${target.destinationPort}`,
          sourceIp: sourceHosts.length === 1 ? sourceHosts[0] : null,
          destinationIp: target.destinationIp,
          protocol: "TCP",
          sourcePort: sources.length === 1 ? Number(sources[0].slice(sources[0].lastIndexOf(":") + 1)) : null,
          destinationPort: target.destinationPort,
          affectedPackets: packetCount,
          affectedFlows: flowCount,
          affectedHosts: hostCount,
          packetNumbers,
          flowKeys: [...target.flowKeys],
          evidence: [
            ...target.evidence.map((item) => `#${item.packetNumber} SYN${item.sequenceNumber === undefined ? "" : ` sequence ${item.sequenceNumber}`}${item.synAckPacketNumber ? `; answered by #${item.synAckPacketNumber}` : "; no matching SYN-ACK observed after timeout"}.`),
            "No matching SYN-ACK was observed in the captured traffic."
          ],
          observed: "Repeated TCP SYN packets without a matching SYN-ACK.",
          whyItMatters: "The connection handshake was not observed to complete during this capture.",
          possibleCauses: [
            "Destination unavailable",
            "Firewall or network filtering",
            "Routing problem",
            "Service not listening",
            "Insufficient capture coverage"
          ],
          recommendedNextStep: "Inspect the listed SYN packets and verify reachability and service availability at the destination.",
          startedAt: earliest ? new Date(earliest).toISOString() : null
        };
      })
      .sort((left, right) => right.priorityScore - left.priorityScore || left.destination.localeCompare(right.destination))
      .slice(0, 5);
  };

  const clear = () => {
    flows.clear();
    capturedPackets = 0;
    decodedTcpPackets = 0;
  };

  const getStatus = () => ({
    status: decodedTcpPackets > 0 ? "ready" : "insufficient",
    message: decodedTcpPackets > 0
      ? null
      : "Insufficient packet metadata to evaluate TCP handshake failures.",
    capturedPackets,
    decodedTcpPackets
  });

  return { ingest, getFindings, getStatus, clear };
};

module.exports = {
  createInvestigationAnalyzer,
  HANDSHAKE_TIMEOUT_MS
};