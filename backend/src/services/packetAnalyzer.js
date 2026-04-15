const SUSPICIOUS_KEYWORDS = ["login", "password", "admin"];

const detectProtocolType = (packet) => {
  const baseProtocol = String(packet.protocol || "").toUpperCase();

  if (baseProtocol.includes("HTTP")) {
    return "HTTP";
  }

  if (baseProtocol.includes("DNS")) {
    return "DNS";
  }

  if (baseProtocol.includes("TCP")) {
    return "TCP";
  }

  if (baseProtocol.includes("UDP")) {
    return "UDP";
  }

  // Simple fallback: check text fields for common protocol hints.
  const textBlob = [packet.payload, packet.data, packet.info]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (textBlob.includes("http")) {
    return "HTTP";
  }

  if (textBlob.includes("dns")) {
    return "DNS";
  }

  return baseProtocol || "UNKNOWN";
};

const detectSuspiciousMatch = (packet) => {
  const textBlob = [packet.payload, packet.data, packet.info]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) =>
    textBlob.includes(keyword)
  );

  return {
    isSuspicious: matchedKeywords.length > 0,
    matchedKeywords
  };
};

const analyzePacket = (packet) => {
  const protocolType = detectProtocolType(packet);
  const suspiciousCheck = detectSuspiciousMatch(packet);

  return {
    sourceIp: packet.sourceIp || "",
    destinationIp: packet.destinationIp || "",
    protocol: packet.protocol || "UNKNOWN",
    protocolType,
    timestamp: packet.timestamp || new Date().toISOString(),
    alert: suspiciousCheck.isSuspicious,
    matchedKeywords: suspiciousCheck.matchedKeywords,
    rawPacket: packet
  };
};

module.exports = {
  analyzePacket
};
