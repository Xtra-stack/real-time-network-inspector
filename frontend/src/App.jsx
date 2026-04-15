import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import PacketTable from "./components/PacketTable";
import AlertPacketList from "./components/AlertPacketList";
import TrafficCharts from "./components/TrafficCharts";

const SOCKET_URL = "http://localhost:5000";

const App = () => {
  const [packets, setPackets] = useState([]);

  const alertCount = packets.filter((packet) => packet.alert).length;
  const protocolCount = new Set(
    packets.map((packet) => packet.protocolType || packet.protocol || "UNKNOWN")
  ).size;

  useEffect(() => {
    const socket = io(SOCKET_URL);

    socket.on("connect", () => {
      console.log("Socket connected:", socket.id);
    });

    socket.on("packet", (packet) => {
      console.log("Incoming packet:", packet);
      setPackets((previousPackets) => [packet, ...previousPackets].slice(0, 100));
    });

    socket.on("disconnect", () => {
      console.log("Socket disconnected");
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return (
    <div className="page">
      <div className="app-shell">
        <header className="header">
          <h1>Real-Time Network Monitoring Dashboard</h1>
          <p>Live packet visibility and alert tracking</p>
        </header>

        <section className="stats-grid">
          <article className="stat-card">
            <p className="stat-label">Total Packets</p>
            <p className="stat-value">{packets.length}</p>
          </article>

          <article className="stat-card">
            <p className="stat-label">Suspicious Alerts</p>
            <p className="stat-value">{alertCount}</p>
          </article>

          <article className="stat-card">
            <p className="stat-label">Active Protocols</p>
            <p className="stat-value">{protocolCount}</p>
          </article>
        </section>

        <main className="dashboard">
          <section className="card card-wide">
            <div className="card-head">
              <h2>Live Feed</h2>
              <span className="card-meta">Latest 100 packets</span>
            </div>
            <PacketTable packets={packets} />
          </section>

          <section className="card">
            <div className="card-head">
              <h2>Suspicious Alerts</h2>
              <span className="card-meta">Red-flag packets</span>
            </div>
            <AlertPacketList packets={packets} />
          </section>

          <section className="card">
            <div className="card-head">
              <h2>Traffic Charts</h2>
              <span className="card-meta">Live overview</span>
            </div>
            <TrafficCharts packets={packets} />
          </section>
        </main>
      </div>
    </div>
  );
};

export default App;
