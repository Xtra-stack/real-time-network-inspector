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

const PacketTable = ({ packets }) => {
  const recentPackets = packets.slice(0, 10);

  if (!packets.length) {
    return <p className="table-empty">Waiting for live packet data...</p>;
  }

  return (
    <div className="table-wrapper">
      <table className="packet-table">
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {recentPackets.map((packet, index) => (
            <tr
              key={`${packet.timestamp}-${packet.sourceIp}-${index}`}
              className={packet.alert ? "packet-row-alert" : ""}
            >
              <td>{packet.sourceIp || "-"}</td>
              <td>{packet.destinationIp || "-"}</td>
              <td>
                <span className="protocol-cell">{packet.protocolType || packet.protocol || "-"}</span>
                {packet.alert ? <span className="packet-alert-badge">ALERT</span> : null}
              </td>
              <td>{formatTimestamp(packet.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default PacketTable;
