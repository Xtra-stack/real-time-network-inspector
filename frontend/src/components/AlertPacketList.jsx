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
    return <p className="alerts-empty">No suspicious packets detected yet.</p>;
  }

  return (
    <ul className="alert-list">
      {alertPackets.map((packet, index) => (
        <li
          key={`${packet.timestamp}-${packet.sourceIp}-${index}`}
          className="alert-item"
        >
          <div className="alert-top">
            <span className="alert-badge">ALERT</span>
            <span className="alert-protocol">{packet.protocolType || packet.protocol || "-"}</span>
          </div>
          <p>
            {packet.sourceIp || "-"} {"->"} {packet.destinationIp || "-"}
          </p>
          <p className="alert-time">{formatTimestamp(packet.timestamp)}</p>
        </li>
      ))}
    </ul>
  );
};

export default AlertPacketList;
