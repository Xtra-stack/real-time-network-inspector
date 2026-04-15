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
          {packets.map((packet, index) => (
            <tr key={`${packet.timestamp}-${packet.sourceIp}-${index}`}>
              <td>{packet.sourceIp || "-"}</td>
              <td>{packet.destinationIp || "-"}</td>
              <td>{packet.protocolType || packet.protocol || "-"}</td>
              <td>{formatTimestamp(packet.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default PacketTable;
