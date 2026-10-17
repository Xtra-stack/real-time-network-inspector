export const buildProtocolDistribution = (packets) => {
  const counts = packets.reduce((result, packet) => {
    const protocol = packet.protocol || "UNKNOWN";
    result[protocol] = (result[protocol] || 0) + 1;
    return result;
  }, {});

  return Object.entries(counts).map(([protocol, count]) => ({ protocol, count }));
};

export const getProtocolDistributionTotal = (distribution) =>
  distribution.reduce((total, entry) => total + entry.count, 0);