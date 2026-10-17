const test = require("node:test");
const assert = require("node:assert/strict");
const { createInvestigationAnalyzer, HANDSHAKE_TIMEOUT_MS } = require("../src/services/investigationAnalyzer");

const baseTime = Date.parse("2026-10-08T12:00:00.000Z");

const tcpPacket = (packetNumber, sourceIp, sourcePort, destinationIp, destinationPort, flags, options = {}) => ({
  packetNumber,
  timestamp: new Date(baseTime + (options.offsetMs || 0)).toISOString(),
  protocol: "TCP",
  captureLength: 54,
  originalLength: 54,
  ip: { version: 4, source: sourceIp, destination: destinationIp, fragmentOffset: 0 },
  tcp: {
    sourcePort,
    destinationPort,
    sequenceNumber: options.sequenceNumber ?? packetNumber * 100,
    acknowledgementNumber: options.acknowledgementNumber,
    flags
  }
});

test("reports insufficient data until at least one TCP header is decoded", () => {
  const analyzer = createInvestigationAnalyzer();
  assert.equal(analyzer.getStatus().status, "insufficient");
  analyzer.ingest({
    packetNumber: 1,
    timestamp: new Date(baseTime).toISOString(),
    protocol: "UNKNOWN",
    captureLength: 30,
    originalLength: 30,
    ip: { version: 4, source: "192.168.1.20", destination: "10.0.0.15", protocolNumber: 99 }
  });
  assert.equal(analyzer.getStatus().status, "insufficient");
  assert.equal(analyzer.getStatus().capturedPackets, 1);
  assert.equal(analyzer.getStatus().decodedTcpPackets, 0);

  analyzer.ingest(tcpPacket(2, "192.168.1.20", 52144, "10.0.0.15", 443, { ack: true }));
  assert.equal(analyzer.getStatus().status, "ready");
  assert.equal(analyzer.getStatus().decodedTcpPackets, 1);
});

test("completed TCP handshakes are not reported as failures", () => {
  const analyzer = createInvestigationAnalyzer();
  analyzer.ingest(tcpPacket(1, "192.168.1.20", 52144, "10.0.0.15", 443, { syn: true, ack: false }));
  analyzer.ingest(tcpPacket(2, "10.0.0.15", 443, "192.168.1.20", 52144, { syn: true, ack: true }, {
    acknowledgementNumber: 101
  }));

  assert.deepEqual(analyzer.getFindings(baseTime + HANDSHAKE_TIMEOUT_MS + 1), []);
});

test("one SYN-ACK resolves matching retransmissions for the same sequence", () => {
  const analyzer = createInvestigationAnalyzer();
  analyzer.ingest(tcpPacket(1, "192.168.1.20", 52144, "10.0.0.15", 443, { syn: true, ack: false }, {
    sequenceNumber: 100
  }));
  analyzer.ingest(tcpPacket(2, "192.168.1.20", 52144, "10.0.0.15", 443, { syn: true, ack: false }, {
    offsetMs: 1000,
    sequenceNumber: 100
  }));
  analyzer.ingest(tcpPacket(3, "10.0.0.15", 443, "192.168.1.20", 52144, { syn: true, ack: true }, {
    offsetMs: 1500,
    acknowledgementNumber: 101
  }));

  assert.deepEqual(analyzer.getFindings(baseTime + HANDSHAKE_TIMEOUT_MS + 2000), []);
});

test("repeated SYN attempts cluster into one evidence-backed finding", () => {
  const analyzer = createInvestigationAnalyzer();
  analyzer.ingest(tcpPacket(14, "192.168.1.20", 52144, "10.0.0.15", 443, { syn: true, ack: false }, {
    sequenceNumber: 1400
  }));
  analyzer.ingest(tcpPacket(17, "192.168.1.20", 52144, "10.0.0.15", 443, { syn: true, ack: false }, {
    offsetMs: 1000,
    sequenceNumber: 1400
  }));

  assert.deepEqual(analyzer.getFindings(baseTime + 1100), []);

  const findings = analyzer.getFindings(baseTime + HANDSHAKE_TIMEOUT_MS + 1100);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "Possible TCP connection failure");
  assert.equal(findings[0].affectedPackets, 2);
  assert.deepEqual(findings[0].packetNumbers, [14, 17]);
  assert.equal(findings[0].confidence, "medium");
  assert.match(findings[0].evidence[0], /#14 SYN/);
  assert.match(findings[0].evidence[1], /#17 SYN/);
  assert.match(findings[0].evidence[2], /No matching SYN-ACK/);
  assert.equal(findings[0].priority, "LOW");
});

test("independent failed flows raise priority deterministically", () => {
  const analyzer = createInvestigationAnalyzer();
  const attempts = [
    [1, "192.168.1.20", 51001],
    [2, "192.168.1.21", 51002],
    [3, "192.168.1.22", 51003],
    [4, "192.168.1.23", 51004]
  ];

  for (const [packetNumber, sourceIp, sourcePort] of attempts) {
    analyzer.ingest(tcpPacket(packetNumber, sourceIp, sourcePort, "10.0.0.15", 443, { syn: true, ack: false }));
  }

  const finding = analyzer.getFindings(baseTime + HANDSHAKE_TIMEOUT_MS + 1)[0];
  assert.equal(finding.affectedFlows, 4);
  assert.equal(finding.affectedHosts, 4);
  assert.equal(finding.priority, "HIGH");
  assert.equal(finding.priorityScore, 68);
});