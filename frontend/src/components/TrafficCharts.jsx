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
import { buildProtocolDistribution, getProtocolDistributionTotal } from "../utils/packetMetrics";

const PIE_COLORS = ["#4f83ff", "#00a878", "#ff9f1c", "#e76f51", "#9c89b8"];

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
  const protocolData = buildProtocolDistribution(packets);
  const protocolTotal = getProtocolDistributionTotal(protocolData);
  const trafficData = buildTrafficData(packets);

  return (
    <div className="charts-grid">
      {!packets.length ? (
        <p className="chart-validation-error charts-empty" role="status">
          Waiting for packet data to draw charts.
        </p>
      ) : null}
      {protocolTotal !== packets.length ? (
        <p className="chart-validation-error" role="alert">
          Protocol distribution mismatch: {protocolTotal} classified of {packets.length} displayed packets.
        </p>
      ) : null}
      <div className="chart-card">
        <h3>Protocol Distribution</h3>
        <p className="chart-total">{protocolTotal} of {packets.length} displayed packets</p>
        <div className="chart-area">
          {packets.length ? (
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
          ) : <p className="chart-panel-empty">Waiting for data</p>}
        </div>
      </div>

      <div className="chart-card">
        <h3>Traffic Over Time</h3>
        <div className="chart-area">
          {packets.length ? (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={trafficData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Line type="monotone" dataKey="count" stroke="#4f83ff" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          ) : <p className="chart-panel-empty">Waiting for data</p>}
        </div>
      </div>
    </div>
  );
};

export default TrafficCharts;
