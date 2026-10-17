const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCaptureRecord, LINKTYPE_ETHERNET, createPacketSummary } = require("../src/services/packetParser");
const {
  normalizeStoredPacket,
  createPacketSummary: createApiPacketSummary,
  getPacketDetails,
  getPackets
} = require("../src/controllers/packetController");
const { createStoragePacket } = require("../src/services/sniffer");
const PacketLog = require("../src/models/PacketLog");

const sourceMac = Buffer.from("001122334455", "hex");
const destinationMac = Buffer.from("aabbccddeeff", "hex");
const sourceIp = Buffer.from([192, 168, 1, 10]);
const destinationIp = Buffer.from([203, 0, 113, 7]);

const ethernetFrame = (etherType, payload) => Buffer.concat([
  destinationMac,
  sourceMac,
  Buffer.from([etherType >> 8, etherType & 0xff]),
  payload
]);

const ipv4Frame = (protocol, payload, options = {}) => {
  const header = Buffer.alloc(20);
  header[0] = 0x45;
  header[1] = 0x2e;
  header.writeUInt16BE(header.length + payload.length, 2);
  header.writeUInt16BE(options.identification ?? 0x1234, 4);
  header.writeUInt16BE(options.fragment ?? 0x4000, 6);
  header[8] = 61;
  header[9] = protocol;
  header.writeUInt16BE(0x3456, 10);
  sourceIp.copy(header, 12);
  destinationIp.copy(header, 16);
  return ethernetFrame(0x0800, Buffer.concat([header, payload]));
};

const tcpSegment = (flags, options = {}) => {
  const tcpOptions = options.options || Buffer.alloc(0);
  const paddedOptions = Buffer.concat([tcpOptions, Buffer.alloc((4 - tcpOptions.length % 4) % 4)]);
  const header = Buffer.alloc(20 + paddedOptions.length);
  header.writeUInt16BE(options.sourcePort ?? 52144, 0);
  header.writeUInt16BE(options.destinationPort ?? 443, 2);
  header.writeUInt32BE(options.sequenceNumber ?? 0x01020304, 4);
  header.writeUInt32BE(options.acknowledgementNumber ?? 0x05060708, 8);
  header[12] = ((header.length / 4) << 4) | ((flags >> 8) & 1);
  header[13] = flags & 0xff;
  header.writeUInt16BE(0x4000, 14);
  header.writeUInt16BE(0x789a, 16);
  header.writeUInt16BE(0, 18);
  paddedOptions.copy(header, 20);
  return header;
};

const captureRecord = (bytes, originalLength = bytes.length, packetNumber = 1) => parseCaptureRecord({
  timestamp: "2026-10-08T12:00:00.000000Z",
  captureLength: bytes.length,
  originalLength,
  linkType: LINKTYPE_ETHERNET,
  bytes: bytes.toString("base64")
}, packetNumber);

test("decodes Ethernet and IPv4 TCP SYN with preserved lengths and exact raw bytes", () => {
  const frame = ipv4Frame(6, tcpSegment(0x002));
  const packet = captureRecord(frame, frame.length + 12, 101);

  assert.equal(packet.packetNumber, 101);
  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.ethernet.sourceMac, "00:11:22:33:44:55");
  assert.equal(packet.ethernet.destinationMac, "aa:bb:cc:dd:ee:ff");
  assert.equal(packet.ethernet.etherType, 0x0800);
  assert.equal(packet.ip.version, 4);
  assert.equal(packet.ip.source, "192.168.1.10");
  assert.equal(packet.ip.destination, "203.0.113.7");
  assert.equal(packet.ip.headerLength, 20);
  assert.equal(packet.ip.totalLength, 40);
  assert.equal(packet.ip.ttl, 61);
  assert.equal(packet.ip.checksum, 0x3456);
  assert.equal(packet.tcp.sourcePort, 52144);
  assert.equal(packet.tcp.destinationPort, 443);
  assert.equal(packet.tcp.sequenceNumber, 0x01020304);
  assert.equal(packet.tcp.acknowledgementNumber, 0x05060708);
  assert.equal(packet.tcp.headerLength, 20);
  assert.equal(packet.tcp.windowSize, 0x4000);
  assert.equal(packet.tcp.checksum, 0x789a);
  assert.equal(packet.tcp.flags.syn, true);
  assert.equal(packet.tcp.flags.ack, false);
  assert.equal(packet.captureLength, frame.length);
  assert.equal(packet.originalLength, frame.length + 12);
  assert.equal(packet.raw.bytes, frame.toString("base64"));
  assert.equal(packet.raw.hex, frame.toString("hex"));
  assert.equal(packet.raw.ascii.length, frame.length);
  assert.equal(packet.rawStatus, "AVAILABLE");
});

test("decodes TCP SYN-ACK and TCP acknowledgement flags", () => {
  const synAckFrame = ipv4Frame(6, tcpSegment(0x012, { acknowledgementNumber: 0x01020305 }));
  const ackFrame = ipv4Frame(6, tcpSegment(0x010));
  const synAck = captureRecord(synAckFrame, synAckFrame.length, 2);
  const ack = captureRecord(ackFrame, ackFrame.length, 3);

  assert.equal(synAck.tcp.flags.syn, true);
  assert.equal(synAck.tcp.flags.ack, true);
  assert.equal(synAck.tcp.acknowledgementNumber, 0x01020305);
  assert.equal(ack.tcp.flags.ack, true);
  assert.equal(ack.tcp.flags.syn, false);
});

test("decodes TCP RST and TCP options from actual header bytes", () => {
  const options = Buffer.from([2, 4, 0x05, 0xb4, 1, 1, 4, 2]);
  const frame = ipv4Frame(6, tcpSegment(0x004, { options }));
  const packet = captureRecord(frame);

  assert.equal(packet.tcp.flags.rst, true);
  assert.equal(packet.tcp.options[0].name, "Maximum Segment Size");
  assert.equal(packet.tcp.options[0].value, 1460);
  assert.equal(packet.tcp.options[3].name, "SACK Permitted");
});

test("identical retransmitted TCP bytes preserve sequence and original packet numbers", () => {
  const frame = ipv4Frame(6, tcpSegment(0x002, { sequenceNumber: 9001 }));
  const first = captureRecord(frame, frame.length, 1101);
  const retransmission = captureRecord(frame, frame.length, 1104);

  assert.equal(first.tcp.sequenceNumber, retransmission.tcp.sequenceNumber);
  assert.equal(first.raw.hex, retransmission.raw.hex);
  assert.equal(first.packetNumber, 1101);
  assert.equal(retransmission.packetNumber, 1104);
});

test("decodes UDP DNS header and preserves UDP checksum and length", () => {
  const dns = Buffer.from("1a2b01000001000000000000", "hex");
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(53000, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + dns.length, 4);
  udp.writeUInt16BE(0x55aa, 6);
  const frame = ipv4Frame(17, Buffer.concat([udp, dns]));
  const packet = captureRecord(frame);

  assert.equal(packet.protocol, "DNS");
  assert.equal(packet.udp.sourcePort, 53000);
  assert.equal(packet.udp.destinationPort, 53);
  assert.equal(packet.udp.length, 20);
  assert.equal(packet.udp.checksum, 0x55aa);
  assert.equal(packet.dns.id, 0x1a2b);
  assert.equal(packet.dns.questionCount, 1);
  assert.equal(packet.raw.hex, frame.toString("hex"));
});

test("decodes ICMP type, code, checksum, identifier, and sequence", () => {
  const icmp = Buffer.from("0800123400110022", "hex");
  const packet = captureRecord(ipv4Frame(1, icmp));

  assert.equal(packet.protocol, "ICMP");
  assert.deepEqual(packet.icmp, {
    type: 8,
    code: 0,
    checksum: 0x1234,
    version: 4,
    identifier: 0x0011,
    sequenceNumber: 0x0022
  });
  assert.equal(packet.payload.length, 0);
});

test("decodes ARP request addresses and Ethernet addresses", () => {
  const arp = Buffer.alloc(28);
  arp.writeUInt16BE(1, 0);
  arp.writeUInt16BE(0x0800, 2);
  arp[4] = 6;
  arp[5] = 4;
  arp.writeUInt16BE(1, 6);
  sourceMac.copy(arp, 8);
  Buffer.from([192, 168, 1, 10]).copy(arp, 14);
  Buffer.alloc(6).copy(arp, 18);
  Buffer.from([192, 168, 1, 1]).copy(arp, 24);
  const frame = ethernetFrame(0x0806, arp);
  const packet = captureRecord(frame);

  assert.equal(packet.protocol, "ARP");
  assert.equal(packet.arp.operationName, "request");
  assert.equal(packet.arp.senderMac, "00:11:22:33:44:55");
  assert.equal(packet.arp.senderIp, "192.168.1.10");
  assert.equal(packet.arp.targetMac, "00:00:00:00:00:00");
  assert.equal(packet.arp.targetIp, "192.168.1.1");
  assert.equal(packet.raw.hex, frame.toString("hex"));
});

test("decodes IPv6 TCP and formats IPv6 source and destination", () => {
  const tcp = tcpSegment(0x010, { sourcePort: 30000, destinationPort: 22 });
  const ip = Buffer.alloc(40);
  ip[0] = 0x60;
  ip.writeUInt16BE(tcp.length, 4);
  ip[6] = 6;
  ip[7] = 48;
  Buffer.from("20010db8000000000000000000000001", "hex").copy(ip, 8);
  Buffer.from("20010db8000000000000000000000002", "hex").copy(ip, 24);
  const frame = ethernetFrame(0x86dd, Buffer.concat([ip, tcp]));
  const packet = captureRecord(frame);

  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.ip.version, 6);
  assert.equal(packet.ip.source, "2001:db8::1");
  assert.equal(packet.ip.destination, "2001:db8::2");
  assert.equal(packet.tcp.sourcePort, 30000);
  assert.equal(packet.tcp.destinationPort, 22);
  assert.equal(packet.tcp.flags.ack, true);
});

test("retains the IPv6 base Next Header when an extension header precedes TCP", () => {
  const tcp = tcpSegment(0x002);
  const hopByHop = Buffer.alloc(8);
  hopByHop[0] = 6;
  hopByHop[1] = 0;
  const ip = Buffer.alloc(40);
  ip[0] = 0x60;
  ip.writeUInt16BE(hopByHop.length + tcp.length, 4);
  ip[6] = 0;
  ip[7] = 64;
  Buffer.from("20010db8000000000000000000000001", "hex").copy(ip, 8);
  Buffer.from("20010db8000000000000000000000002", "hex").copy(ip, 24);
  const packet = captureRecord(ethernetFrame(0x86dd, Buffer.concat([ip, hopByHop, tcp])));

  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.ip.nextHeader, 0);
  assert.equal(packet.ip.protocolNumber, 6);
  assert.equal(packet.ip.extensionHeaders[0].type, 0);
  assert.equal(packet.tcp.flags.syn, true);
});

test("decodes VLAN tagging and retains the inner Ethernet protocol", () => {
  const ipv4 = ipv4Frame(6, tcpSegment(0x002)).subarray(14);
  const tagged = Buffer.concat([
    destinationMac,
    sourceMac,
    Buffer.from("810000640800", "hex"),
    ipv4
  ]);
  const packet = captureRecord(tagged);

  assert.equal(packet.ethernet.etherType, 0x0800);
  assert.equal(packet.ethernet.vlan.length, 1);
  assert.equal(packet.ethernet.vlan[0].id, 100);
  assert.equal(packet.protocol, "TCP");
});

test("decodes ICMPv6 echo request fields", () => {
  const icmp = Buffer.from("8000123400110022", "hex");
  const ip = Buffer.alloc(40);
  ip[0] = 0x60;
  ip.writeUInt16BE(icmp.length, 4);
  ip[6] = 58;
  ip[7] = 64;
  Buffer.from("20010db8000000000000000000000001", "hex").copy(ip, 8);
  Buffer.from("20010db8000000000000000000000002", "hex").copy(ip, 24);
  const packet = captureRecord(ethernetFrame(0x86dd, Buffer.concat([ip, icmp])));

  assert.equal(packet.protocol, "ICMPv6");
  assert.equal(packet.icmp.type, 128);
  assert.equal(packet.icmp.code, 0);
  assert.equal(packet.icmp.checksum, 0x1234);
  assert.equal(packet.icmp.identifier, 0x0011);
  assert.equal(packet.icmp.sequenceNumber, 0x0022);
});

test("detects DHCP only after a valid BOOTP magic cookie", () => {
  const dhcp = Buffer.alloc(244);
  dhcp[0] = 1;
  dhcp[1] = 1;
  dhcp[2] = 6;
  dhcp.writeUInt32BE(0x10203040, 4);
  sourceMac.copy(dhcp, 28);
  Buffer.from("63825363", "hex").copy(dhcp, 236);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(68, 0);
  udp.writeUInt16BE(67, 2);
  udp.writeUInt16BE(252, 4);
  const packet = captureRecord(ipv4Frame(17, Buffer.concat([udp, dhcp])));

  assert.equal(packet.protocol, "DHCP");
  assert.equal(packet.dhcp.transactionId, 0x10203040);
  assert.equal(packet.dhcp.clientMac, "00:11:22:33:44:55");
});

test("detects TLS, HTTP, SSH, FTP, and SMTP from captured payload bytes", () => {
  const applicationCases = [
    { name: "TLS", port: 443, payload: Buffer.from("1603010004aabbccdd", "hex") },
    { name: "HTTP", port: 80, payload: Buffer.from("GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n") },
    { name: "SSH", port: 22, payload: Buffer.from("SSH-2.0-OpenSSH_9.0\r\n") },
    { name: "FTP", port: 21, payload: Buffer.from("220 FTP service ready\r\n") },
    { name: "SMTP", port: 25, payload: Buffer.from("220 mail SMTP ready\r\n") }
  ];

  for (const [index, entry] of applicationCases.entries()) {
    const tcp = tcpSegment(0x010, { destinationPort: entry.port });
    const packet = captureRecord(ipv4Frame(6, Buffer.concat([tcp, entry.payload])), undefined, index + 1);
    assert.equal(packet.protocol, entry.name);
    assert.equal(packet.payload.hex, entry.payload.toString("hex"));
  }
});

test("does not label unknown network protocols as OTHER or as TCP", () => {
  const packet = captureRecord(ipv4Frame(99, Buffer.from([1, 2, 3, 4])));
  const invalidVersionIcmp = captureRecord(ipv4Frame(58, Buffer.from("8000123400110022", "hex")), undefined, 2);
  assert.equal(packet.protocol, "UNKNOWN");
  assert.equal(packet.tcp, undefined);
  assert.equal(packet.udp, undefined);
  assert.equal(invalidVersionIcmp.protocol, "UNKNOWN");
  assert.equal(invalidVersionIcmp.icmp, undefined);
});

test("rejects records whose declared lengths do not match real bytes", () => {
  assert.throws(() => parseCaptureRecord({
    timestamp: "2026-10-08T12:00:00.000Z",
    captureLength: 10,
    originalLength: 10,
    linkType: LINKTYPE_ETHERNET,
    bytes: Buffer.alloc(9).toString("base64")
  }, 1), /lengths do not match/);
});

test("packet API normalization reparses persisted bytes into the canonical packet shape", () => {
  const frame = ipv4Frame(6, tcpSegment(0x012, { acknowledgementNumber: 0x01020305 }));
  const packet = normalizeStoredPacket({
    packetNumber: 84,
    captureId: "capture-a",
    timestamp: new Date("2026-10-08T12:00:00.000Z"),
    captureLength: frame.length,
    originalLength: frame.length,
    linkType: LINKTYPE_ETHERNET,
    raw: { bytes: frame.toString("base64"), encoding: "base64" },
    protocol: "TCP"
  });

  assert.equal(packet.packetNumber, 84);
  assert.equal(packet.captureId, "capture-a");
  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.tcp.sequenceNumber, 0x01020304);
  assert.equal(packet.tcp.acknowledgementNumber, 0x01020305);
  assert.equal(packet.raw.hex, frame.toString("hex"));
  assert.equal(packet.payload.length, 0);
});

test("packet list projection stays lightweight while retaining real decoded metadata", () => {
  const frame = ipv4Frame(6, tcpSegment(0x012, { acknowledgementNumber: 0x01020305 }));
  const stored = {
    packetNumber: 85,
    captureId: "capture-a",
    timestamp: new Date("2026-10-08T12:00:00.000Z"),
    captureLength: frame.length,
    originalLength: frame.length,
    linkType: LINKTYPE_ETHERNET,
    raw: { bytes: frame.toString("base64"), encoding: "base64" },
    protocol: "TCP"
  };
  const listPacket = createApiPacketSummary(normalizeStoredPacket(stored, { includeRaw: false }));

  assert.equal(listPacket.protocol, "TCP");
  assert.equal(listPacket.tcp.sourcePort, 52144);
  assert.equal(listPacket.tcp.acknowledgementNumber, 0x01020305);
  assert.equal(listPacket.rawStatus, "AVAILABLE");
  assert.equal(listPacket.raw, undefined);
  assert.equal(listPacket.payload, undefined);
});

test("packet list API applies protocol and text filters with pagination metadata", async () => {
  const storedPackets = [
    {
      packetNumber: 10,
      captureId: "capture-a",
      timestamp: new Date("2026-10-08T12:00:00.000Z"),
      protocol: "TCP",
      captureLength: 60,
      originalLength: 60,
      linkType: 1,
      source: "192.168.1.10",
      destination: "203.0.113.7",
      tcp: { sourcePort: 52144, destinationPort: 443 },
      raw: { bytes: Buffer.alloc(60).toString("base64") }
    },
    {
      packetNumber: 11,
      captureId: "capture-a",
      timestamp: new Date("2026-10-08T12:00:01.000Z"),
      protocol: "UDP",
      captureLength: 64,
      originalLength: 64,
      linkType: 1,
      source: "192.168.1.11",
      destination: "8.8.8.8",
      udp: { sourcePort: 62657, destinationPort: 53 },
      raw: { bytes: Buffer.alloc(64).toString("base64") }
    },
    {
      packetNumber: 12,
      captureId: "capture-b",
      timestamp: new Date("2026-10-08T12:00:02.000Z"),
      protocol: "TCP",
      captureLength: 58,
      originalLength: 58,
      linkType: 1,
      source: "10.0.0.5",
      destination: "10.0.0.12",
      tcp: { sourcePort: 8080, destinationPort: 443 },
      raw: { bytes: Buffer.alloc(58).toString("base64") }
    }
  ];

  const originalFind = PacketLog.find;
  const originalCountDocuments = PacketLog.countDocuments;
  const requestQuery = { q: "443", protocol: "TCP" };
  const matchesQuery = (packet) => {
    const text = String(requestQuery.q ?? "").trim();
    const protocol = String(requestQuery.protocol ?? "").trim();
    if (protocol && packet.protocol.toUpperCase() !== protocol.toUpperCase()) return false;
    if (!text) return true;
    const haystacks = [
      packet.packetNumber,
      packet.protocol,
      packet.info,
      packet.captureId,
      packet.source,
      packet.destination,
      packet.ip?.source,
      packet.ip?.destination,
      packet.tcp?.sourcePort,
      packet.tcp?.destinationPort,
      packet.udp?.sourcePort,
      packet.udp?.destinationPort
    ];
    return haystacks.some((value) => String(value ?? "").toLowerCase().includes(text.toLowerCase()));
  };

  PacketLog.find = () => {
    const matches = storedPackets
      .filter((packet) => matchesQuery(packet))
      .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp));
    return {
      sort: () => ({
        skip: () => ({
          limit: (limit) => ({
            lean: async () => matches.slice(0, limit)
          })
        })
      })
    };
  };
  PacketLog.countDocuments = async () => storedPackets.filter((packet) => matchesQuery(packet)).length;

  try {
    let responseStatus;
    let responseBody;
    await getPackets({
      query: { q: "443", protocol: "TCP", page: "1", limit: "1" }
    }, {
      status(code) { responseStatus = code; return this; },
      json(body) { responseBody = body; return this; }
    });

    assert.equal(responseStatus, 200);
    assert.equal(responseBody.page, 1);
    assert.equal(responseBody.pageSize, 1);
    assert.equal(responseBody.total, 2);
    assert.equal(responseBody.packets.length, 1);
    assert.equal(responseBody.packets[0].packetNumber, 12);
    assert.equal(responseBody.packets[0].protocol, "TCP");
  } finally {
    PacketLog.find = originalFind;
    PacketLog.countDocuments = originalCountDocuments;
  }
});

test("selected packet detail handler returns decoded raw bytes on demand", async () => {
  const udp = Buffer.alloc(12);
  udp.writeUInt16BE(52144, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(udp.length, 4);
  udp.writeUInt16BE(0x1234, 6);
  Buffer.from("01020304", "hex").copy(udp, 8);
  const frame = ipv4Frame(17, udp);
  const stored = {
    packetNumber: 86,
    captureId: "capture-detail",
    timestamp: new Date("2026-10-08T12:00:00.000Z"),
    captureLength: frame.length,
    originalLength: frame.length,
    linkType: LINKTYPE_ETHERNET,
    raw: { bytes: frame.toString("base64"), encoding: "base64" },
    protocol: "UDP"
  };
  const originalFindOne = PacketLog.findOne;
  let responseStatus;
  let responseBody;
  PacketLog.findOne = () => ({ lean: async () => stored });
  try {
    await getPacketDetails({ params: { captureId: "capture-detail", packetNumber: "86" } }, {
      status(code) { responseStatus = code; return this; },
      json(body) { responseBody = body; return this; }
    });
  } finally {
    PacketLog.findOne = originalFindOne;
  }

  assert.equal(responseStatus, 200);
  assert.equal(responseBody.raw.hex, frame.toString("hex"));
  assert.equal(responseBody.udp.sourcePort, 52144);
  assert.equal(responseBody.payload.hex, "01020304");
});

test("normalizes common libpcap aliases before parsing the captured bytes", () => {
  const frame = ipv4Frame(6, tcpSegment(0x012, { acknowledgementNumber: 101 }));
  const packet = parseCaptureRecord({
    header: {
      ts: { tv_sec: 1791460800, tv_usec: 250000 },
      caplen: frame.length,
      len: frame.length + 4,
      datalink: LINKTYPE_ETHERNET
    },
    data: { type: "Buffer", data: [...frame] }
  }, 902);

  assert.equal(packet.packetNumber, 902);
  assert.equal(packet.captureLength, frame.length);
  assert.equal(packet.originalLength, frame.length + 4);
  assert.equal(packet.linkType, LINKTYPE_ETHERNET);
  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.tcp.acknowledgementNumber, 101);
  assert.equal(packet.raw.hex, frame.toString("hex"));
});

test("converts stale flattened capture summaries into explicit partial normalized records", () => {
  const packet = parseCaptureRecord({
    sourceIp: "192.168.1.10",
    destinationIp: "203.0.113.7",
    protocol: "TCP",
    timestamp: "2026-10-08T12:00:00.000Z"
  }, 1109);

  assert.equal(packet.packetNumber, 1109);
  assert.equal(packet.protocol, "TCP");
  assert.equal(packet.source, "192.168.1.10");
  assert.equal(packet.destination, "203.0.113.7");
  assert.deepEqual(packet.ip, { source: "192.168.1.10", destination: "203.0.113.7" });
  assert.equal(packet.decodeStatus, "PARTIAL");
  assert.equal(packet.captureLength, undefined);
  assert.equal(packet.tcp, undefined);
  assert.equal(packet.raw, undefined);
  assert.equal(packet.rawStatus, "RAW_BYTES_UNAVAILABLE");
});

test("live packet summary omits byte bodies but advertises that details are available", () => {
  const frame = ipv4Frame(6, tcpSegment(0x002));
  const packet = captureRecord(frame, frame.length, 150);
  const summary = createPacketSummary(packet);

  assert.equal(summary.packetNumber, 150);
  assert.equal(summary.protocol, "TCP");
  assert.equal(summary.rawStatus, "AVAILABLE");
  assert.equal(summary.raw, undefined);
  assert.equal(summary.payload, undefined);
});

test("live partial packet summary exposes why raw bytes are unavailable", () => {
  const packet = parseCaptureRecord({
    sourceIp: "192.168.1.10",
    destinationIp: "203.0.113.7",
    protocol: "TCP",
    timestamp: "2026-10-08T12:00:00.000Z"
  }, 151);
  const summary = createPacketSummary(packet);

  assert.equal(summary.rawStatus, "RAW_BYTES_UNAVAILABLE");
  assert.match(summary.rawUnavailableReason, /without the original frame bytes/);
  assert.equal(summary.raw, undefined);
});

test("safe capture diagnostics report field names and byte counts, never byte contents", () => {
  const { summarizeCaptureRecord } = require("../src/services/packetParser");
  const rawBytes = Buffer.from("secret-frame-content");
  const summary = summarizeCaptureRecord({
    timestamp: "2026-10-08T12:00:00.000Z",
    data: rawBytes,
    sourceIp: "192.168.1.10"
  });

  assert.deepEqual(summary.availableFields, ["data", "sourceIp", "timestamp"]);
  assert.equal(summary.rawValueType, "buffer");
  assert.equal(summary.sourcePresent, true);
  assert.equal(JSON.stringify(summary).includes("secret-frame-content"), false);
});

test("summary-only capture records persist without dereferencing or fabricating raw bytes", () => {
  const packet = parseCaptureRecord({
    sourceIp: "192.168.1.10",
    destinationIp: "203.0.113.7",
    protocol: "TCP",
    timestamp: "2026-10-08T12:00:00.000Z"
  }, 1109);
  const storedPacket = createStoragePacket({ ...packet, captureId: "capture-test" });
  const model = new PacketLog(storedPacket);

  assert.equal(model.validateSync(), undefined);
  assert.equal(storedPacket.packetNumber, 1109);
  assert.equal(storedPacket.ip.source, "192.168.1.10");
  assert.equal(storedPacket.raw, undefined);
  assert.equal(storedPacket.captureLength, undefined);
  assert.equal(storedPacket.decodeStatus, "PARTIAL");
});

test("full packet storage retains exactly the raw base64 frame and omits derived payload copies", () => {
  const frame = ipv4Frame(6, tcpSegment(0x002));
  const packet = captureRecord(frame, frame.length, 99);
  const storedPacket = createStoragePacket(packet);

  assert.equal(storedPacket.raw.bytes, frame.toString("base64"));
  assert.equal(storedPacket.raw.hex, undefined);
  assert.equal(storedPacket.payload, undefined);
});

test("legacy API rows disclose that raw frame bytes were not retained", () => {
  const packet = normalizeStoredPacket({
    packetNumber: 15,
    captureId: "old-capture",
    sourceIp: "192.168.1.10",
    destinationIp: "203.0.113.7",
    protocol: "TCP",
    timestamp: new Date("2026-10-08T12:00:00.000Z"),
    packetLength: 54,
    capturedLength: 54
  });

  assert.equal(packet.decodeStatus, "legacy-summary");
  assert.equal(packet.raw, null);
  assert.equal(packet.ip.source, "192.168.1.10");
  assert.equal(packet.info, "Legacy summary only; original frame bytes were not stored.");
});