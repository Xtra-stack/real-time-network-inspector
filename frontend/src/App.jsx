import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import PacketTable from "./components/PacketTable";
import AlertPacketList from "./components/AlertPacketList";
import TrafficCharts from "./components/TrafficCharts";

const SOCKET_URL = "http://localhost:5000";

const App = () => {
  const [packets, setPackets] = useState([]);

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
      <header className="header">
        <h1>Real-Time Network Monitoring Dashboard</h1>
        <p>Live packet visibility and alert tracking</p>
      </header>

      <main className="dashboard">
        <section className="card">
          <h2>Live Feed</h2>
          <p>Incoming packet activity count: {packets.length}</p>
          <PacketTable packets={packets} />
        </section>

        <section className="card">
          <h2>Suspicious Alerts</h2>
          <AlertPacketList packets={packets} />
        </section>

        <section className="card">
          <h2>Traffic Charts</h2>
          <TrafficCharts packets={packets} />
        </section>
      </main>
    </div>
  );
};

export default App;
