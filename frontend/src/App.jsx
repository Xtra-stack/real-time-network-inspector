import { useEffect, useRef, useState } from "react";
import { io } from "socket.io-client";
import PacketTable from "./components/PacketTable";
import StartHere from "./components/StartHere";
import TrafficCharts from "./components/TrafficCharts";

const SOCKET_URL = "http://localhost:5000";
const API_BASE_URL = "http://localhost:5000/api";
const PACKET_WINDOW_SIZE = 500;

const App = () => {
  const [packets, setPackets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [capturedCount, setCapturedCount] = useState(0);
  const [investigationStatus, setInvestigationStatus] = useState({
    status: "insufficient",
    message: "Insufficient packet metadata to evaluate TCP handshake failures.",
    capturedPackets: 0,
    decodedTcpPackets: 0
  });
  const [focusedFinding, setFocusedFinding] = useState(null);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packetDetails, setPacketDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState("");
  const [interfaceList, setInterfaceList] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [interfaceError, setInterfaceError] = useState("");
  const [captureStatus, setCaptureStatus] = useState({
    status: "Idle",
    selectedInterface: "",
    interfaces: [],
    lastError: "",
    packetStats: { received: 0, processed: 0, dropped: 0 }
  });
  const [captureActionLoading, setCaptureActionLoading] = useState(null);
  const activeCaptureId = useRef(null);
  const detailRequestId = useRef(0);

  const visiblePackets = focusedFinding
    ? packets.filter((packet) =>
        packet.captureId === focusedFinding.captureId &&
        focusedFinding.packetNumbers.includes(packet.packetNumber)
      )
    : packets;

  const protocolCount = new Set(
    packets.map((packet) => packet.protocol || "UNKNOWN")
  ).size;

  const refreshInterfaces = async () => {
    setInterfacesLoading(true);
    setInterfaceError("");
    try {
      const response = await fetch(`${API_BASE_URL}/capture/interfaces`);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.message || "Interface discovery failed. Check the backend capture-provider status.");
      }
      const interfaces = Array.isArray(data) ? data : Array.isArray(data.interfaces) ? data.interfaces : null;
      if (!interfaces) throw new Error("The interface API returned an unexpected response format.");
      setInterfaceList(interfaces);
      setSelectedInterface((current) => {
        if (interfaces.some((entry) => (entry.deviceId || entry.name) === current)) {
          return current;
        }
        const firstSupported = interfaces.find((entry) => entry.captureSupported) || interfaces[0];
        return firstSupported ? (firstSupported.deviceId || firstSupported.name || "") : "";
      });
      if (!interfaces.length) setInterfaceError("Npcap returned no network devices. Check the driver service and backend permissions.");
    } catch (error) {
      setInterfaceError(error.message || "Unable to load interfaces.");
    } finally {
      setInterfacesLoading(false);
    }
  };

  const loadCaptureStatus = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/capture/status`);
      if (!response.ok) throw new Error("Capture status request failed.");
      const status = await response.json();
      setCaptureStatus({
        status: status.status || "Idle",
        selectedInterface: status.selectedInterface || "",
        interfaces: Array.isArray(status.interfaces) ? status.interfaces : [],
        lastError: status.lastError || "",
        packetStats: status.packetStats || { received: 0, processed: 0, dropped: 0 }
      });
      if (status.selectedInterface) {
        setSelectedInterface(status.selectedInterface);
      }
    } catch (error) {
      console.error("Failed to fetch capture status:", error);
    }
  };

  const submitCaptureAction = async (action, payload = null) => {
    setCaptureActionLoading(action);
    setInterfaceError("");

    try {
      const response = await fetch(`${API_BASE_URL}/capture/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload ? JSON.stringify(payload) : undefined
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.message || `Capture ${action} request failed.`);
      }
      if (data.status) {
        setCaptureStatus((current) => ({ ...current, status: data.status }));
      }
      await loadCaptureStatus();
    } catch (error) {
      setInterfaceError(error.message || "Capture action failed.");
      setCaptureStatus((current) => ({ ...current, lastError: error.message || "Capture action failed." }));
    } finally {
      setCaptureActionLoading(null);
    }
  };

  useEffect(() => {
    let socket;
    let isMounted = true;

    const initializeDashboard = async () => {
      try {
        const packetsResponse = await fetch(`${API_BASE_URL}/packets`);
        if (!packetsResponse.ok) throw new Error("Packet history request failed");
        const packetData = await packetsResponse.json();
        const listPackets = Array.isArray(packetData)
          ? packetData
          : Array.isArray(packetData?.packets)
            ? packetData.packets
            : [];

        if (isMounted) {
          const historicalPackets = listPackets.slice(0, PACKET_WINDOW_SIZE);
          const captureId = historicalPackets.find((packet) => packet.captureId)?.captureId || null;
          activeCaptureId.current = captureId;
          const capturePackets = captureId
            ? historicalPackets.filter((packet) => packet.captureId === captureId)
            : historicalPackets;
          setPackets(capturePackets);
          setCapturedCount(capturePackets.reduce((maximum, packet) =>
            Number.isInteger(packet.packetNumber) ? Math.max(maximum, packet.packetNumber) : maximum, 0));
        }
      } catch (error) {
        console.error("Failed to load initial packet data:", error);
      }

      if (!isMounted) return;
      refreshInterfaces();
      loadCaptureStatus();

      socket = io(SOCKET_URL);

      socket.on("connect", () => {
        console.log("Socket connected:", socket.id);
      });

      socket.on("capture-status", (status) => {
        const nextStatus = status || {};
        setCaptureStatus({
          status: nextStatus.status || "Idle",
          selectedInterface: nextStatus.selectedInterface || "",
          interfaces: Array.isArray(nextStatus.interfaces) ? nextStatus.interfaces : [],
          lastError: nextStatus.lastError || "",
          packetStats: nextStatus.packetStats || { received: 0, processed: 0, dropped: 0 }
        });
        if (nextStatus.selectedInterface) {
          setSelectedInterface(nextStatus.selectedInterface);
        }
      });

      socket.on("packet", (packet) => {
        const sameCapture = activeCaptureId.current === packet.captureId;
        activeCaptureId.current = packet.captureId;
        setCapturedCount((previousCount) => sameCapture
          ? Math.max(previousCount, packet.packetNumber || 0)
          : packet.packetNumber || 0);
        setPackets((previousPackets) => {
          const capturePackets = previousPackets.filter((existing) => existing.captureId === packet.captureId);
          if (capturePackets.some((existing) => existing.packetNumber === packet.packetNumber)) {
            return capturePackets;
          }
          return [packet, ...capturePackets].slice(0, PACKET_WINDOW_SIZE);
        });
      });

      socket.on("investigations", (update) => {
        if (!update || typeof update !== "object") return;
        const captureChanged = update.captureId && activeCaptureId.current !== update.captureId;
        activeCaptureId.current = update.captureId || activeCaptureId.current;
        setInvestigationStatus(update);
        setFindings(Array.isArray(update.findings) ? update.findings : []);
        if (Number.isInteger(update.capturedPackets)) {
          setCapturedCount((previousCount) => captureChanged ? update.capturedPackets : Math.max(previousCount, update.capturedPackets));
        }
        if (captureChanged) {
          setPackets((previousPackets) => previousPackets.filter((packet) => packet.captureId === update.captureId));
          setFocusedFinding(null);
          setSelectedPacket(null);
          setPacketDetails(null);
          setDetailsLoading(false);
          setDetailsError("");
        }
      });

      socket.on("disconnect", () => {
        console.log("Socket disconnected");
      });
    };

    initializeDashboard();

    return () => {
      isMounted = false;
      if (socket) {
        socket.removeAllListeners();
        socket.disconnect();
      }
    };
  }, []);

  const selectPacket = async (packet) => {
    const requestId = ++detailRequestId.current;
    setSelectedPacket(packet);
    setPacketDetails(null);
    setDetailsError("");
    setDetailsLoading(packet.rawStatus === "AVAILABLE" && Boolean(packet.captureId));

    if (packet.rawStatus !== "AVAILABLE" || !packet.captureId) return;

    try {
      const response = await fetch(
        `${API_BASE_URL}/packets/${encodeURIComponent(packet.captureId)}/${encodeURIComponent(packet.packetNumber)}`
      );
      if (!response.ok) throw new Error("Packet details are not available from storage.");
      const details = await response.json();
      if (requestId === detailRequestId.current) setPacketDetails(details);
    } catch (error) {
      if (requestId === detailRequestId.current) setDetailsError(error.message);
    } finally {
      if (requestId === detailRequestId.current) setDetailsLoading(false);
    }
  };

  const investigateFinding = (finding) => {
    setFocusedFinding(finding);
    const evidenceNumbers = new Set(finding.packetNumbers);
    const firstEvidencePacket = packets.find((packet) =>
      packet.captureId === finding.captureId && evidenceNumbers.has(packet.packetNumber)
    );
    if (firstEvidencePacket) selectPacket(firstEvidencePacket);
  };

  const clearInvestigation = () => {
    detailRequestId.current += 1;
    setFocusedFinding(null);
    setSelectedPacket(null);
    setPacketDetails(null);
    setDetailsLoading(false);
    setDetailsError("");
  };

  return (
    <div className="page">
      <div className="app-shell">
        <header className="header">
          <div className="header-content">
            <div>
              <h1>Network Inspector</h1>
              <p>Live packet triage and investigation priorities</p>
            </div>
            <div className="capture-toolbar">
              <label className="interface-picker">
                <span>Interface</span>
                <select
                  value={selectedInterface}
                  onChange={(event) => setSelectedInterface(event.target.value)}
                  disabled={interfacesLoading}
                >
                  <option value="">Select an interface</option>
                  {interfaceList.map((entry) => (
                    <option
                      key={entry.deviceId || entry.name}
                      value={entry.deviceId || entry.name}
                      disabled={!entry.captureSupported}
                      title={entry.captureError || entry.description || ""}
                    >
                      {entry.friendlyName || entry.name || entry.deviceId || "Unnamed interface"}
                      {entry.type && entry.type !== "Unknown" ? ` (${entry.type})` : ""}
                      {entry.captureSupported ? "" : ` (unavailable${entry.captureError ? `: ${entry.captureError}` : ""})`}
                    </option>
                  ))}
                </select>
              </label>

              <button type="button" onClick={() => refreshInterfaces()} disabled={interfacesLoading}>
                {interfacesLoading ? "Refreshing..." : "Refresh interfaces"}
              </button>

              <button
                type="button"
                onClick={() => submitCaptureAction("start", { interfaceName: selectedInterface || captureStatus.selectedInterface || "" })}
                disabled={captureActionLoading !== null || !selectedInterface || ["Starting", "Running", "Paused", "Stopping"].includes(captureStatus.status)}
              >
                {captureActionLoading === "start" ? "Starting..." : "Start"}
              </button>

              <button
                type="button"
                onClick={() => submitCaptureAction("pause")}
                disabled={captureActionLoading !== null || captureStatus.status !== "Running"}
              >
                {captureActionLoading === "pause" ? "Pausing..." : "Pause"}
              </button>

              <button
                type="button"
                onClick={() => submitCaptureAction("resume")}
                disabled={captureActionLoading !== null || captureStatus.status !== "Paused"}
              >
                {captureActionLoading === "resume" ? "Resuming..." : "Resume"}
              </button>

              <button
                type="button"
                onClick={() => submitCaptureAction("stop")}
                disabled={captureActionLoading !== null || !["Running", "Paused", "Starting", "Stopping"].includes(captureStatus.status)}
              >
                {captureActionLoading === "stop" ? "Stopping..." : "Stop"}
              </button>
            </div>
          </div>

          <div className="capture-status-row">
            <span className={`status-badge status-${String(captureStatus.status || "idle").toLowerCase()}`}>
              {captureStatus.status || "Idle"}
            </span>
            <span className="capture-status-text">
              {interfaceList.find((entry) => (entry.deviceId || entry.name) === (selectedInterface || captureStatus.selectedInterface))?.friendlyName || captureStatus.selectedInterface || "No interface selected"}
            </span>
          </div>
        </header>

        {(interfaceError || captureStatus.lastError) ? (
          <div className="capture-alert">
            {interfaceError || captureStatus.lastError}
          </div>
        ) : null}

        <section className="stats-grid">
          <article className="stat-card">
            <p className="stat-label">Packets Shown</p>
            <p className="stat-value">{packets.length}</p>
          </article>

          <article className="stat-card">
            <p className="stat-label">Captured Total</p>
            <p className="stat-value">{capturedCount}</p>
          </article>

          <article className="stat-card">
            <p className="stat-label">Active Protocols</p>
            <p className="stat-value">{protocolCount}</p>
          </article>
        </section>

        <StartHere
          findings={findings}
          status={investigationStatus.status}
          statusMessage={investigationStatus.message}
          decodedTcpPackets={investigationStatus.decodedTcpPackets}
          onInvestigate={investigateFinding}
        />

        <main className="dashboard">
          <section className="card card-wide">
            <div className="card-head">
              <div>
                <h2>{focusedFinding ? "Finding Evidence" : "Packet Capture"}</h2>
                <span className="card-meta">
                  {focusedFinding
                    ? `${visiblePackets.length} related packets`
                    : `Showing latest ${packets.length} of ${capturedCount} captured packets`}
                </span>
              </div>
              {focusedFinding ? (
                <button className="clear-investigation" type="button" onClick={clearInvestigation}>
                  Clear investigation filter
                </button>
              ) : null}
            </div>
            <PacketTable
              packets={visiblePackets}
              selectedPacket={selectedPacket}
              packetDetails={packetDetails}
              detailsLoading={detailsLoading}
              detailsError={detailsError}
              onSelectPacket={selectPacket}
              focusedPacketNumbers={focusedFinding ? focusedFinding.packetNumbers : []}
            />
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
