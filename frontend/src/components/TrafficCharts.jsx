import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend
} from "recharts";

const PIE_COLORS = ["#4f83ff", "#00a878", "#ff9f1c", "#e76f51", "#9c89b8"];

const buildProtocolData = (packets) => {
  const counts = packets.reduce((result, packet) => {
    const key = packet.protocolType || packet.protocol || "UNKNOWN";
    result[key] = (result[key] || 0) + 1;
    return result;
  }, {});

  return Object.entries(counts).map(([protocol, count]) => ({
    protocol,
    count
  }));
};

const buildTrafficData = (packets) => {
  const sortedPackets = [...packets]
    .filter((packet) => packet.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const counts = sortedPackets.reduce((result, packet) => {
    const timeLabel = new Date(packet.timestamp).toLocaleTimeString();
    result[timeLabel] = (result[timeLabel] || 0) + 1;
    return result;
  }, {});

  return Object.entries(counts).map(([time, count]) => ({
    time,
    count
  }));
};

const TrafficCharts = ({ packets }) => {
  const protocolData = buildProtocolData(packets);
  const trafficData = buildTrafficData(packets);

  if (!packets.length) {
    return <p className="charts-empty">Waiting for data to draw charts...</p>;
  }

  return (
    <div className="charts-grid">
      <div className="chart-card">
        <h3>Protocol Distribution</h3>
        <div className="chart-area">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={protocolData}
                dataKey="count"
                nameKey="protocol"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label
              >
                {protocolData.map((entry, index) => (
                  <Cell
                    key={entry.protocol}
                    fill={PIE_COLORS[index % PIE_COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="chart-card">
        <h3>Traffic Over Time</h3>
        <div className="chart-area">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#4f83ff" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default TrafficCharts;
