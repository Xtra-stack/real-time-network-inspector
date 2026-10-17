const LINKTYPE_ETHERNET = 1;
const VLAN_TYPES = new Set([0x8100, 0x88a8, 0x9100]);

const read16 = (bytes, offset) => bytes.readUInt16BE(offset);
const read32 = (bytes, offset) => bytes.readUInt32BE(offset);

const hasBytes = (bytes, offset, length, end = bytes.length) =>
  Number.isInteger(offset) && Number.isInteger(length) && offset >= 0 && length >= 0 && offset + length <= end;

const formatMac = (bytes, offset) => [...bytes.subarray(offset, offset + 6)]
  .map((part) => part.toString(16).padStart(2, "0"))
  .join(":");

const formatIPv4 = (bytes, offset) => [...bytes.subarray(offset, offset + 4)].join(".");

const formatIPv6 = (bytes, offset) => {
  const groups = Array.from({ length: 8 }, (_, index) => read16(bytes, offset + index * 2).toString(16));
  let bestStart = -1;
  let bestLength = 1;

  for (let index = 0; index < groups.length;) {
    if (groups[index] !== "0") {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === "0") end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  if (bestStart < 0) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
};

const hex = (bytes) => bytes.toString("hex").match(/.{1,2}/g)?.join(" ") || "";

const ascii = (bytes) => [...bytes]
  .map((value) => value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".")
  .join("");

const parseTcpOptions = (bytes, start, headerEnd) => {
  const options = [];
  let offset = start;

  while (offset < headerEnd) {
    const kind = bytes[offset];
    if (kind === 0) {
      options.push({ kind, name: "End of Option List" });
      break;
    }
    if (kind === 1) {
      options.push({ kind, name: "No-Operation" });
      offset += 1;
      continue;
    }
    if (!hasBytes(bytes, offset, 2, headerEnd)) break;
    const length = bytes[offset + 1];
    if (length < 2 || !hasBytes(bytes, offset, length, headerEnd)) break;

    const option = { kind, length, name: `Option ${kind}`, valueHex: bytes.subarray(offset + 2, offset + length).toString("hex") };
    if (kind === 2 && length === 4) {
      option.name = "Maximum Segment Size";
      option.value = read16(bytes, offset + 2);
    } else if (kind === 3 && length === 3) {
      option.name = "Window Scale";
      option.value = bytes[offset + 2];
    } else if (kind === 4 && length === 2) {
      option.name = "SACK Permitted";
    } else if (kind === 8 && length === 10) {
      option.name = "Timestamps";
      option.value = [read32(bytes, offset + 2), read32(bytes, offset + 6)];
    }
    options.push(option);
    offset += length;
  }

  return options;
};

const decodeDns = (payload, isTcp) => {
  let offset = 0;
  if (isTcp) {
    if (!hasBytes(payload, 0, 2)) return null;
    const messageLength = read16(payload, 0);
    if (messageLength < 12 || !hasBytes(payload, 2, messageLength)) return null;
    offset = 2;
  }
  if (!hasBytes(payload, offset, 12)) return null;
  const flags = read16(payload, offset + 2);
  return {
    id: read16(payload, offset),
    response: Boolean(flags & 0x8000),
    opcode: (flags >> 11) & 0x0f,
    authoritative: Boolean(flags & 0x0400),
    truncated: Boolean(flags & 0x0200),
    recursionDesired: Boolean(flags & 0x0100),
    recursionAvailable: Boolean(flags & 0x0080),
    responseCode: flags & 0x000f,
    questionCount: read16(payload, offset + 4),
    answerCount: read16(payload, offset + 6),
    authorityCount: read16(payload, offset + 8),
    additionalCount: read16(payload, offset + 10)
  };
};

const detectApplicationProtocol = (payload, transport, sourcePort, destinationPort) => {
  const ports = [sourcePort, destinationPort];
  const startsWith = (text) => payload.subarray(0, Buffer.byteLength(text)).toString("ascii") === text;

  if (ports.includes(53)) {
    const dns = decodeDns(payload, transport === "TCP");
    if (dns) return { protocol: "DNS", decoded: { dns } };
  }

  if (ports.some((port) => [67, 68].includes(port)) &&
      hasBytes(payload, 0, 240) && payload.subarray(236, 240).equals(Buffer.from([0x63, 0x82, 0x53, 0x63]))) {
    return {
      protocol: "DHCP",
      decoded: {
        dhcp: {
          operation: payload[0],
          transactionId: read32(payload, 4),
          clientAddress: formatIPv4(payload, 12),
          yourAddress: formatIPv4(payload, 16),
          serverAddress: formatIPv4(payload, 20),
          clientMac: formatMac(payload, 28)
        }
      }
    };
  }

  if ((payload[0] === 0x16 || payload[0] === 0x14 || payload[0] === 0x15 || payload[0] === 0x17) &&
      payload[1] === 0x03 && payload.length >= 5 && read16(payload, 3) <= payload.length - 5) {
    return {
      protocol: "TLS",
      decoded: { tls: { recordType: payload[0], version: `0x${payload.subarray(1, 3).toString("hex")}`, recordLength: read16(payload, 3) } }
    };
  }

  if (startsWith("SSH-")) return { protocol: "SSH", decoded: { ssh: { identification: payload.subarray(0, 255).toString("ascii").split(/[\r\n]/, 1)[0] } } };

  const startLine = payload.subarray(0, Math.min(payload.length, 512)).toString("latin1").split("\r\n", 1)[0];
  const httpMethod = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP\/1\.[01]$/.test(startLine);
  const httpResponse = /^HTTP\/1\.[01] [1-5]\d\d(?: |$)/.test(startLine);
  if ((ports.some((port) => [80, 8000, 8080, 8081].includes(port)) || httpMethod || httpResponse) && (httpMethod || httpResponse)) {
    return { protocol: "HTTP", decoded: { http: { startLine } } };
  }

  if ((ports.includes(21) && (/^(220 |USER |PASS |220-)/.test(startLine))) || /^220 .*FTP/i.test(startLine)) {
    return { protocol: "FTP", decoded: { ftp: { startLine } } };
  }
  if ((ports.some((port) => [25, 465, 587].includes(port)) && /^(220 |250 |EHLO |HELO |MAIL FROM:|RCPT TO:)/i.test(startLine)) || /^220 .*SMTP/i.test(startLine)) {
    return { protocol: "SMTP", decoded: { smtp: { startLine } } };
  }

  return null;
};

const decodeBase64 = (value) => {
  if (typeof value !== "string" || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError("Invalid captured frame encoding");
  }
  return Buffer.from(value, "base64");
};

const getTimestamp = (record, header) => {
  const value = record.timestamp ?? record.ts ?? header.ts;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
  if (typeof value === "string") return Number.isNaN(Date.parse(value)) ? undefined : value;
  if (typeof value === "number" && Number.isFinite(value)) {
    const milliseconds = Math.abs(value) < 100000000000 ? value * 1000 : value;
    return new Date(milliseconds).toISOString();
  }
  if (value && typeof value === "object" && Number.isFinite(value.tv_sec)) {
    const microseconds = Number.isFinite(value.tv_usec) ? value.tv_usec : 0;
    return new Date(value.tv_sec * 1000 + microseconds / 1000).toISOString();
  }
  return undefined;
};

const getCapturedBytes = (record) => {
  const raw = record.raw;
  const candidates = [
    [record.bytes, record.encoding || "base64"],
    [record.data, record.dataEncoding || "bytes"],
    [record.raw, record.rawEncoding || "bytes"],
    [raw?.bytes, raw?.encoding || record.rawEncoding || "base64"],
    [raw?.data, raw?.encoding || "bytes"],
    [record.packet, record.packetEncoding || "bytes"],
    [record.packet?.bytes, record.packet?.encoding || "base64"],
    [record.packet?.data, record.packet?.encoding || "bytes"],
    [record.header?.data, record.header?.encoding || "bytes"]
  ];

  for (const [value, encoding] of candidates) {
    if (Buffer.isBuffer(value)) return value;
    if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
      return Buffer.from(value);
    }
    if (value && value.type === "Buffer" && Array.isArray(value.data)) return Buffer.from(value.data);
    if (typeof value === "string" && value.length) {
      if (encoding === "hex" && value.length % 2 === 0 && /^[\da-f]*$/i.test(value)) return Buffer.from(value, "hex");
      if (encoding === "base64") return decodeBase64(value);
    }
  }

  if (typeof raw?.hex === "string" && raw.hex.length % 2 === 0 && /^[\da-f]*$/i.test(raw.hex)) {
    return Buffer.from(raw.hex, "hex");
  }
  if (record.rawHex && typeof record.rawHex === "string" && record.rawHex.length % 2 === 0 && /^[\da-f]*$/i.test(record.rawHex)) {
    return Buffer.from(record.rawHex, "hex");
  }
  return null;
};

const normalizeCaptureEnvelope = (record, packetNumber) => {
  if (!record || typeof record !== "object" || !Number.isInteger(packetNumber)) {
    throw new TypeError("Capture record is missing required packet metadata");
  }

  const header = record.header && typeof record.header === "object" ? record.header : {};
  const captureLength = record.captureLength ?? record.caplen ?? header.captureLength ?? header.caplen;
  const originalLength = record.originalLength ?? record.len ?? header.originalLength ?? header.len;
  const linkType = record.linkType ?? record.datalink ?? record.linktype ?? header.linkType ?? header.datalink;
  const timestamp = getTimestamp(record, header);
  const bytes = getCapturedBytes(record);

  if (bytes) {
    if (!Number.isInteger(captureLength) || !Number.isInteger(originalLength) || !Number.isInteger(linkType)) {
      throw new TypeError("Raw capture is missing captureLength/caplen, originalLength/len, or linkType metadata");
    }
    return {
      kind: "raw",
      timestamp,
      captureLength,
      originalLength,
      linkType,
      bytes,
      bytesBase64: bytes.toString("base64")
    };
  }

  const source = record.source ?? record.sourceIp ?? record.src;
  const destination = record.destination ?? record.destinationIp ?? record.dst;
  const suppliedProtocol = typeof record.protocol === "string" ? record.protocol.toUpperCase() : undefined;
  const protocol = suppliedProtocol === "OTHER" ? "UNKNOWN" : suppliedProtocol;
  if (timestamp && (source || destination || protocol)) {
    return {
      kind: "summary",
      timestamp,
      captureLength: Number.isInteger(captureLength) ? captureLength : undefined,
      originalLength: Number.isInteger(originalLength) ? originalLength : undefined,
      linkType: Number.isInteger(linkType) ? linkType : undefined,
      source,
      destination,
      protocol: protocol || "UNKNOWN",
      sourcePort: Number.isInteger(record.sourcePort ?? record.srcPort) ? (record.sourcePort ?? record.srcPort) : undefined,
      destinationPort: Number.isInteger(record.destinationPort ?? record.dstPort) ? (record.destinationPort ?? record.dstPort) : undefined
    };
  }

  throw new TypeError("Capture record is missing required packet metadata and captured frame bytes");
};

const validateNormalizedPacket = (packet) => {
  if (!Number.isInteger(packet.packetNumber) || !packet.timestamp || !packet.protocol) {
    throw new TypeError("Normalized packet is missing packetNumber, timestamp, or protocol");
  }
  if (packet.decodeStatus === "PARTIAL") return packet;
  if (!Number.isInteger(packet.captureLength) || !Number.isInteger(packet.originalLength) ||
      !Number.isInteger(packet.linkType) || !packet.raw?.bytes || !packet.raw?.hex) {
    throw new TypeError("Normalized packet is missing validated frame bytes or capture metadata");
  }
  if (Buffer.from(packet.raw.bytes, "base64").length !== packet.captureLength || packet.originalLength < packet.captureLength) {
    throw new RangeError("Normalized packet capture lengths do not match the captured frame bytes");
  }
  return packet;
};

const normalizeSummaryPacket = (record, packetNumber) => {
  const summary = normalizeCaptureEnvelope(record, packetNumber);
  const packet = {
    packetNumber,
    timestamp: summary.timestamp,
    protocol: summary.protocol,
    info: "Capture source supplied a metadata summary without raw frame bytes.",
    decodeStatus: "PARTIAL",
    rawStatus: "RAW_BYTES_UNAVAILABLE",
    rawUnavailableReason: "Capture source supplied a metadata summary without the original frame bytes."
  };
  if (summary.captureLength !== undefined) packet.captureLength = summary.captureLength;
  if (summary.originalLength !== undefined) packet.originalLength = summary.originalLength;
  if (summary.linkType !== undefined) packet.linkType = summary.linkType;
  if (summary.source !== undefined) packet.source = summary.source;
  if (summary.destination !== undefined) packet.destination = summary.destination;
  if (summary.source !== undefined || summary.destination !== undefined) {
    packet.ip = {};
    if (summary.source !== undefined) packet.ip.source = summary.source;
    if (summary.destination !== undefined) packet.ip.destination = summary.destination;
  }
  if (summary.sourcePort !== undefined || summary.destinationPort !== undefined) {
    packet.transportSummary = {};
    if (summary.sourcePort !== undefined) packet.transportSummary.sourcePort = summary.sourcePort;
    if (summary.destinationPort !== undefined) packet.transportSummary.destinationPort = summary.destinationPort;
  }
  return validateNormalizedPacket(packet);
};

const parseCaptureRecord = (record, packetNumber) => {
  const envelope = normalizeCaptureEnvelope(record, packetNumber);
  if (envelope.kind === "summary") return normalizeSummaryPacket(record, packetNumber);
  const { timestamp, captureLength, originalLength, linkType, bytes, bytesBase64 } = envelope;
  if (!timestamp) throw new TypeError("Raw capture is missing a valid timestamp");

  if (bytes.length !== captureLength || originalLength < captureLength) {
    throw new RangeError("Capture record lengths do not match the captured frame bytes");
  }

  const packet = {
    packetNumber,
    timestamp,
    captureLength,
    originalLength,
    linkType,
    protocol: "UNKNOWN",
    info: "Undecoded captured frame",
    rawStatus: "AVAILABLE",
    raw: { bytes: bytesBase64, encoding: "base64", hex: bytes.toString("hex"), ascii: ascii(bytes) },
    payload: { length: bytes.length, hex: bytes.toString("hex"), ascii: ascii(bytes) }
  };

  if (linkType !== LINKTYPE_ETHERNET || !hasBytes(bytes, 0, 14)) {
    packet.info = linkType === LINKTYPE_ETHERNET ? "Truncated Ethernet frame" : `Unsupported link type ${linkType}`;
    return validateNormalizedPacket(packet);
  }

  let etherType = read16(bytes, 12);
  let offset = 14;
  const vlan = [];
  while (VLAN_TYPES.has(etherType) && hasBytes(bytes, offset, 4)) {
    vlan.push({ tagProtocol: etherType, id: read16(bytes, offset) & 0x0fff, priority: read16(bytes, offset) >> 13 });
    etherType = read16(bytes, offset + 2);
    offset += 4;
  }

  packet.ethernet = {
    destinationMac: formatMac(bytes, 0),
    sourceMac: formatMac(bytes, 6),
    etherType,
    vlan
  };
  packet.payload = {
    length: Math.max(0, bytes.length - offset),
    hex: bytes.subarray(offset).toString("hex"),
    ascii: ascii(bytes.subarray(offset))
  };

  if (etherType === 0x0806 && hasBytes(bytes, offset, 8)) {
    const hardwareLength = bytes[offset + 4];
    const protocolLength = bytes[offset + 5];
    const addressLength = hardwareLength + protocolLength;
    if (hardwareLength === 6 && protocolLength === 4 && hasBytes(bytes, offset + 8, addressLength * 2)) {
      const senderMacOffset = offset + 8;
      const senderIpOffset = senderMacOffset + hardwareLength;
      const targetMacOffset = senderIpOffset + protocolLength;
      const targetIpOffset = targetMacOffset + hardwareLength;
      const operation = read16(bytes, offset + 6);
      packet.arp = {
        operation,
        operationName: operation === 1 ? "request" : operation === 2 ? "reply" : "unknown",
        senderMac: formatMac(bytes, senderMacOffset),
        senderIp: formatIPv4(bytes, senderIpOffset),
        targetMac: formatMac(bytes, targetMacOffset),
        targetIp: formatIPv4(bytes, targetIpOffset)
      };
      packet.source = packet.arp.senderIp;
      packet.destination = packet.arp.targetIp;
      packet.protocol = "ARP";
      packet.payload = { length: Math.max(0, bytes.length - (offset + 8 + addressLength * 2)), hex: bytes.subarray(offset + 8 + addressLength * 2).toString("hex"), ascii: ascii(bytes.subarray(offset + 8 + addressLength * 2)) };
      packet.info = `ARP ${packet.arp.operationName} ${packet.arp.senderIp} -> ${packet.arp.targetIp}`;
    } else {
      packet.info = "ARP frame with unsupported address sizes";
    }
    return validateNormalizedPacket(packet);
  }

  if (etherType !== 0x0800 && etherType !== 0x86dd) {
    packet.info = `Ethernet II, EtherType 0x${etherType.toString(16).padStart(4, "0")}`;
    return validateNormalizedPacket(packet);
  }

  const ipv6 = etherType === 0x86dd;
  const minimumIpHeaderLength = ipv6 ? 40 : 20;
  if (!hasBytes(bytes, offset, minimumIpHeaderLength)) {
    packet.protocol = ipv6 ? "IPv6" : "IPv4";
    packet.info = `Truncated ${packet.protocol} header`;
    return validateNormalizedPacket(packet);
  }

  let transportOffset;
  let transportProtocol;
  let ipEnd;
  if (ipv6) {
    if ((bytes[offset] >> 4) !== 6) {
      packet.info = "EtherType and IP version do not match";
      return packet;
    }
    const payloadLength = read16(bytes, offset + 4);
    ipEnd = Math.min(bytes.length, offset + 40 + payloadLength);
    const baseNextHeader = bytes[offset + 6];
    let nextHeader = baseNextHeader;
    transportOffset = offset + 40;
    let fragmentOffset = 0;
    let extensionCount = 0;
    const extensionHeaders = [];
    while ([0, 43, 44, 51, 60, 135, 139, 140].includes(nextHeader) && extensionCount < 8) {
      if (!hasBytes(bytes, transportOffset, 2, ipEnd)) break;
      const extensionType = nextHeader;
      nextHeader = bytes[transportOffset];
      const extensionLength = extensionType === 44 ? 8 : extensionType === 51
        ? (bytes[transportOffset + 1] + 2) * 4
        : (bytes[transportOffset + 1] + 1) * 8;
      if (!hasBytes(bytes, transportOffset, extensionLength, ipEnd)) break;
      if (extensionType === 44) fragmentOffset = (read16(bytes, transportOffset + 2) >> 3) & 0x1fff;
      extensionHeaders.push({ type: extensionType, length: extensionLength, nextHeader });
      transportOffset += extensionLength;
      extensionCount += 1;
    }
    transportProtocol = nextHeader;
    packet.ip = {
      version: 6,
      trafficClass: ((bytes[offset] & 0x0f) << 4) | (bytes[offset + 1] >> 4),
      flowLabel: ((bytes[offset + 1] & 0x0f) << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3],
      headerLength: transportOffset - offset,
      totalLength: 40 + payloadLength,
      payloadLength,
      nextHeader: baseNextHeader,
      protocolNumber: nextHeader,
      extensionHeaders,
      hopLimit: bytes[offset + 7],
      source: formatIPv6(bytes, offset + 8),
      destination: formatIPv6(bytes, offset + 24),
      fragmentOffset,
      checksum: null
    };
  } else {
    if ((bytes[offset] >> 4) !== 4) {
      packet.info = "EtherType and IP version do not match";
      return packet;
    }
    const headerLength = (bytes[offset] & 0x0f) * 4;
    const totalLength = read16(bytes, offset + 2);
    if (headerLength < 20 || !hasBytes(bytes, offset, headerLength) || totalLength < headerLength) {
      packet.protocol = "IPv4";
      packet.info = "Invalid or truncated IPv4 header";
      return packet;
    }
    const fragmentField = read16(bytes, offset + 6);
    ipEnd = Math.min(bytes.length, offset + totalLength);
    transportOffset = offset + headerLength;
    transportProtocol = bytes[offset + 9];
    packet.ip = {
      version: 4,
      headerLength,
      dscp: bytes[offset + 1] >> 2,
      totalLength,
      identification: read16(bytes, offset + 4),
      flags: { reserved: Boolean(fragmentField & 0x8000), dontFragment: Boolean(fragmentField & 0x4000), moreFragments: Boolean(fragmentField & 0x2000) },
      fragmentOffset: fragmentField & 0x1fff,
      ttl: bytes[offset + 8],
      protocolNumber: transportProtocol,
      checksum: read16(bytes, offset + 10),
      source: formatIPv4(bytes, offset + 12),
      destination: formatIPv4(bytes, offset + 16)
    };
  }

  packet.source = packet.ip.source;
  packet.destination = packet.ip.destination;

  packet.protocol = "UNKNOWN";
  const isNonInitialFragment = (packet.ip.fragmentOffset || 0) > 0;
  const availablePayload = bytes.subarray(Math.min(transportOffset, ipEnd), ipEnd);
  let applicationPayload = availablePayload;

  if (!isNonInitialFragment && transportProtocol === 6 && hasBytes(bytes, transportOffset, 20, ipEnd)) {
    const headerLength = (bytes[transportOffset + 12] >> 4) * 4;
    if (headerLength >= 20 && hasBytes(bytes, transportOffset, headerLength, ipEnd)) {
      const flagBits = (bytes[transportOffset + 12] & 1) << 8 | bytes[transportOffset + 13];
      packet.tcp = {
        sourcePort: read16(bytes, transportOffset),
        destinationPort: read16(bytes, transportOffset + 2),
        sequenceNumber: read32(bytes, transportOffset + 4),
        acknowledgementNumber: read32(bytes, transportOffset + 8),
        headerLength,
        flags: {
          fin: Boolean(flagBits & 0x001), syn: Boolean(flagBits & 0x002), rst: Boolean(flagBits & 0x004),
          psh: Boolean(flagBits & 0x008), ack: Boolean(flagBits & 0x010), urg: Boolean(flagBits & 0x020),
          ece: Boolean(flagBits & 0x040), cwr: Boolean(flagBits & 0x080), ns: Boolean(flagBits & 0x100)
        },
        windowSize: read16(bytes, transportOffset + 14),
        checksum: read16(bytes, transportOffset + 16),
        urgentPointer: read16(bytes, transportOffset + 18),
        options: parseTcpOptions(bytes, transportOffset + 20, transportOffset + headerLength)
      };
      applicationPayload = bytes.subarray(transportOffset + headerLength, ipEnd);
      packet.protocol = "TCP";
    }
  } else if (!isNonInitialFragment && transportProtocol === 17 && hasBytes(bytes, transportOffset, 8, ipEnd)) {
    const udpLength = read16(bytes, transportOffset + 4);
    if (udpLength >= 8) {
      packet.udp = {
        sourcePort: read16(bytes, transportOffset),
        destinationPort: read16(bytes, transportOffset + 2),
        length: udpLength,
        checksum: read16(bytes, transportOffset + 6)
      };
      applicationPayload = bytes.subarray(transportOffset + 8, Math.min(ipEnd, transportOffset + udpLength));
      packet.protocol = "UDP";
    }
  } else if (!isNonInitialFragment &&
      ((packet.ip.version === 4 && transportProtocol === 1) || (packet.ip.version === 6 && transportProtocol === 58)) &&
      hasBytes(bytes, transportOffset, 4, ipEnd)) {
    const type = bytes[transportOffset];
    const code = bytes[transportOffset + 1];
    packet.icmp = { type, code, checksum: read16(bytes, transportOffset + 2), version: transportProtocol === 58 ? 6 : 4 };
    if ((type === 0 || type === 8 || type === 128 || type === 129) && hasBytes(bytes, transportOffset, 8, ipEnd)) {
      packet.icmp.identifier = read16(bytes, transportOffset + 4);
      packet.icmp.sequenceNumber = read16(bytes, transportOffset + 6);
    }
    if (transportProtocol === 1 && type === 3 && code === 4 && hasBytes(bytes, transportOffset, 8, ipEnd)) {
      packet.icmp.nextHopMtu = read16(bytes, transportOffset + 6);
    }
    if (transportProtocol === 58 && type === 2 && hasBytes(bytes, transportOffset, 8, ipEnd)) {
      packet.icmp.mtu = read32(bytes, transportOffset + 4);
    }
    packet.protocol = transportProtocol === 58 ? "ICMPv6" : "ICMP";
    applicationPayload = bytes.subarray(transportOffset + (hasBytes(bytes, transportOffset, 8, ipEnd) ? 8 : 4), ipEnd);
  }

  if (packet.tcp || packet.udp) {
    const transport = packet.tcp ? "TCP" : "UDP";
    const sourcePort = packet.tcp?.sourcePort ?? packet.udp?.sourcePort;
    const destinationPort = packet.tcp?.destinationPort ?? packet.udp?.destinationPort;
    const application = detectApplicationProtocol(applicationPayload, transport, sourcePort, destinationPort);
    if (application) {
      packet.protocol = application.protocol;
      Object.assign(packet, application.decoded);
    }
  }

  packet.payload = { length: applicationPayload.length, hex: applicationPayload.toString("hex"), ascii: ascii(applicationPayload) };
  if (packet.tcp) {
    const flags = Object.entries(packet.tcp.flags).filter(([, enabled]) => enabled).map(([name]) => name.toUpperCase()).join(" ");
    packet.info = `TCP${flags ? ` ${flags}` : ""} ${packet.tcp.sourcePort} -> ${packet.tcp.destinationPort}`;
  } else if (packet.udp) {
    packet.info = `${packet.protocol} ${packet.udp.sourcePort} -> ${packet.udp.destinationPort}`;
  } else if (packet.icmp) {
    packet.info = `${packet.protocol} type ${packet.icmp.type} code ${packet.icmp.code}`;
  } else if (packet.arp) {
    packet.info = `ARP ${packet.arp.operationName} ${packet.arp.senderIp} -> ${packet.arp.targetIp}`;
  } else {
    packet.info = `${packet.protocol} ${packet.ip.source} -> ${packet.ip.destination}`;
  }

  return validateNormalizedPacket(packet);
};

const summarizeCaptureRecord = (record) => {
  if (!record || typeof record !== "object") return { receivedType: typeof record };
  const availableFields = Object.keys(record).sort();
  const byteCandidates = [record.bytes, record.data, record.raw?.bytes, record.packet?.bytes, record.packet?.data];
  const byteValue = byteCandidates.find((value) => value !== undefined);
  const header = record.header && typeof record.header === "object" ? record.header : {};
  return {
    availableFields,
    fieldTypes: Object.fromEntries(availableFields.map((field) => [
      field,
      Array.isArray(record[field]) ? "array" : Buffer.isBuffer(record[field]) ? "buffer" : typeof record[field]
    ])),
    timestampPresent: Boolean(record.timestamp ?? record.ts ?? header.ts),
    captureLength: record.captureLength ?? record.caplen ?? header.captureLength ?? header.caplen ?? null,
    originalLength: record.originalLength ?? record.len ?? header.originalLength ?? header.len ?? null,
    linkType: record.linkType ?? record.datalink ?? record.linktype ?? header.linkType ?? header.datalink ?? null,
    protocol: typeof record.protocol === "string" ? record.protocol : null,
    sourcePresent: Boolean(record.source ?? record.sourceIp ?? record.src),
    destinationPresent: Boolean(record.destination ?? record.destinationIp ?? record.dst),
    rawValueType: byteValue === undefined ? "absent" : Buffer.isBuffer(byteValue) ? "buffer" : Array.isArray(byteValue) ? "array" : typeof byteValue,
    rawEncodedLength: typeof byteValue === "string" ? byteValue.length : Array.isArray(byteValue) ? byteValue.length : null,
    nestedHeaderFields: Object.keys(header).sort()
  };
};

const createPacketSummary = (packet) => {
  const { raw, payload, ...summary } = packet;
  const hasRawBytes = typeof raw?.bytes === "string" && raw.bytes.length > 0;
  summary.rawStatus = hasRawBytes ? "AVAILABLE" : packet.rawStatus || "RAW_BYTES_UNAVAILABLE";
  if (summary.rawStatus === "RAW_BYTES_UNAVAILABLE") {
    summary.rawUnavailableReason = packet.rawUnavailableReason ||
      "Capture source did not provide the original frame bytes.";
  }
  return summary;
};

module.exports = {
  parseCaptureRecord,
  normalizeCaptureEnvelope,
  validateNormalizedPacket,
  summarizeCaptureRecord,
  createPacketSummary,
  LINKTYPE_ETHERNET
};