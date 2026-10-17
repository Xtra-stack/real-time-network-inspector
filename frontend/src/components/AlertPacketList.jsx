const formatTimestamp = (value) => {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
};

const AlertPacketList = ({ packets }) => {
  const alertPackets = packets.filter((packet) => packet.alert === true);

  if (!alertPackets.length) {
    return <p className="alerts-empty">No keyword matches in the current packet set.</p>;
  }

  return (
    <ul className="alert-list">
      {alertPackets.map((packet, index) => (
        <li
          key={`${packet.captureId}-${packet.packetNumber}-${index}`}
          className="alert-item"
        >
          <div className="alert-top">
            <span className="alert-badge">MATCH</span>
            <span className="alert-protocol">{packet.protocol || "UNKNOWN"}</span>
          </div>
          <p>
            {packet.ip?.source || packet.arp?.senderIp || "-"} {"->"} {packet.ip?.destination || packet.arp?.targetIp || "-"}
          </p>
          <p className="alert-time">{formatTimestamp(packet.timestamp)}</p>
        </li>
      ))}
    </ul>
  );
};

export default AlertPacketList;
