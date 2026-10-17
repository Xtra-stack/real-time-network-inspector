import { useEffect, useMemo, useState } from "react";

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

const pageSize = 50;
const unavailable = "Unavailable";

const getSource = (packet) => packet.ip?.source || packet.arp?.senderIp || packet.ethernet?.sourceMac || "";
const getDestination = (packet) => packet.ip?.destination || packet.arp?.targetIp || packet.ethernet?.destinationMac || "";
const getSourcePort = (packet) => packet.tcp?.sourcePort ?? packet.udp?.sourcePort;
const getDestinationPort = (packet) => packet.tcp?.destinationPort ?? packet.udp?.destinationPort;
const getFlags = (packet) => packet.tcp
  ? Object.entries(packet.tcp.flags || {}).filter(([, enabled]) => enabled).map(([name]) => name.toUpperCase()).join(" ") || "None"
  : "-";

const sortValue = (packet, key) => {
  if (key === "source") return getSource(packet);
  if (key === "destination") return getDestination(packet);
  if (key === "captureLength") return packet.captureLength ?? -1;
  return packet[key] ?? "";
};

const formatValue = (value) => {
  if (value === null || value === undefined || value === "") return unavailable;
  if (typeof value === "boolean") return value ? "Set" : "Not set";
  if (Array.isArray(value)) return value.length
    ? value.map((item) => item && typeof item === "object"
      ? Object.entries(item).map(([key, nested]) => `${key}: ${nested}`).join(" ")
      : String(item)).join("; ")
    : "None";
  if (typeof value === "object") return Object.entries(value).map(([key, item]) => `${key}: ${item ? "set" : "not set"}`).join("; ");
  return String(value);
};

const getProtocolSections = (packet) => {
  const sections = [
    ["Frame", [
      ["Captured length", Number.isInteger(packet.captureLength) ? `${packet.captureLength} bytes` : unavailable],
      ["Original length", Number.isInteger(packet.originalLength) ? `${packet.originalLength} bytes` : unavailable],
      ["Status", packet.originalLength > packet.captureLength ? "Truncated" : packet.decodeStatus || "Complete capture record"],
      ["Link type", packet.linkType ?? unavailable]
    ]]
  ];
  const definitions = [
    ["Ethernet II", "ethernet"], ["IPv4 / IPv6", "ip"], ["TCP", "tcp"], ["UDP", "udp"],
    ["ICMP / ICMPv6", "icmp"], ["ARP", "arp"], ["DNS", "dns"], ["DHCP", "dhcp"],
    ["TLS", "tls"], ["HTTP", "http"], ["SSH", "ssh"], ["FTP", "ftp"], ["SMTP", "smtp"]
  ];

  for (const [title, key] of definitions) {
    const fields = packet[key];
    if (!fields || typeof fields !== "object") continue;
    sections.push([title, Object.entries(fields).map(([field, value]) => [field, formatValue(value)])]);
  }

  sections.push(["Payload", [
    ["Length", packet.payload ? `${packet.payload.length} bytes` : unavailable],
    ["Hex", packet.payload?.hex || (packet.payload ? "Empty" : unavailable)],
    ["ASCII", packet.payload?.ascii || (packet.payload ? "Empty" : unavailable)]
  ]]);
  return sections;
};

const buildHexRows = (rawHex, rawAscii) => {
  if (typeof rawHex !== "string") return [];
  const rows = [];
  for (let offset = 0; offset < rawHex.length / 2; offset += 16) {
    const hexBytes = rawHex.slice(offset * 2, (offset + 16) * 2).match(/.{2}/g) || [];
    const asciiText = rawAscii?.slice(offset, offset + hexBytes.length) || "";
    rows.push({
      offset: offset.toString(16).padStart(8, "0"),
      hex: hexBytes.join(" ").padEnd(47, " "),
      ascii: [...asciiText].map((character) => character.charCodeAt(0) >= 0x20 && character.charCodeAt(0) <= 0x7e ? character : ".").join("")
    });
  }
  return rows;
};

const PacketTable = ({ packets, selectedPacket, packetDetails, detailsLoading, detailsError, onSelectPacket, focusedPacketNumbers }) => {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState({ key: "packetNumber", direction: "desc" });

  useEffect(() => {
    setPage(0);
  }, [query, packets.length]);

  const matchingPackets = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const filtered = packets.filter((packet) => {
      if (!normalizedQuery) return true;
      return [
        packet.packetNumber,
        packet.timestamp,
        getSource(packet),
        getDestination(packet),
        getSourcePort(packet),
        getDestinationPort(packet),
        packet.protocol,
        packet.info
      ].some((value) => String(value ?? "").toLowerCase().includes(normalizedQuery));
    });

    return filtered.sort((left, right) => {
      const leftValue = sortValue(left, sort.key);
      const rightValue = sortValue(right, sort.key);
      const result = typeof leftValue === "number" && typeof rightValue === "number"
        ? leftValue - rightValue
        : String(leftValue).localeCompare(String(rightValue));
      return sort.direction === "asc" ? result : -result;
    });
  }, [packets, query, sort]);

  const pageCount = Math.max(1, Math.ceil(matchingPackets.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const visiblePackets = matchingPackets.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const inspectedPacket = packetDetails || selectedPacket;

  const changeSort = (key) => {
    setSort((current) => ({
      key,
      direction: current.key === key && current.direction === "desc" ? "asc" : "desc"
    }));
  };

  const sortHeader = (label, key) => (
    <th>
      <button className="sort-button" type="button" onClick={() => changeSort(key)}>
        {label}{sort.key === key ? (sort.direction === "asc" ? " asc" : " desc") : ""}
      </button>
    </th>
  );

  return (
    <>
      <div className="packet-tools">
        <label className="packet-search">
          <span>Search packets</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="IP, protocol, port, packet number" />
        </label>
        <span className="table-count">{matchingPackets.length} packets</span>
      </div>

      {visiblePackets.length ? (
        <div className="table-wrapper">
          <table className="packet-table">
            <thead>
              <tr>
                {sortHeader("No.", "packetNumber")}
                {sortHeader("Time", "timestamp")}
                {sortHeader("Source", "source")}
                {sortHeader("Destination", "destination")}
                {sortHeader("Protocol", "protocol")}
                {sortHeader("Captured length", "captureLength")}
                <th>TCP Flags</th>
                <th>Information</th>
              </tr>
            </thead>
            <tbody>
              {visiblePackets.map((packet, index) => {
                const flags = getFlags(packet);
                const highlighted = focusedPacketNumbers.includes(packet.packetNumber);
                const selected = selectedPacket?.packetNumber === packet.packetNumber && selectedPacket?.captureId === packet.captureId;
                return (
                  <tr
                    key={`${packet.captureId}-${packet.packetNumber}-${packet.timestamp}-${index}`}
                    className={`${packet.alert ? "packet-row-alert " : ""}${highlighted ? "packet-row-evidence " : ""}${selected ? "packet-row-selected" : ""}`}
                    tabIndex={0}
                    onClick={() => onSelectPacket(packet)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onSelectPacket(packet);
                      }
                    }}
                    aria-selected={selected}
                  >
                    <td>{Number.isInteger(packet.packetNumber) ? packet.packetNumber : "-"}</td>
                    <td>{formatTimestamp(packet.timestamp)}</td>
                    <td>{getSource(packet) || unavailable}{Number.isInteger(getSourcePort(packet)) ? `:${getSourcePort(packet)}` : ""}</td>
                    <td>{getDestination(packet) || unavailable}{Number.isInteger(getDestinationPort(packet)) ? `:${getDestinationPort(packet)}` : ""}</td>
                    <td>{packet.protocol || "UNKNOWN"}</td>
                    <td>{Number.isInteger(packet.captureLength) ? `${packet.captureLength} bytes` : unavailable}</td>
                    <td>{flags}</td>
                    <td>{packet.info || unavailable}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="table-empty">{packets.length ? "No packets match this search." : "Waiting for live packet data..."}</p>
      )}

      {matchingPackets.length > pageSize ? (
        <div className="pagination-controls">
          <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={currentPage === 0}>
            Previous
          </button>
          <span>Page {currentPage + 1} of {pageCount}</span>
          <button type="button" onClick={() => setPage((current) => Math.min(pageCount - 1, current + 1))} disabled={currentPage >= pageCount - 1}>
            Next
          </button>
        </div>
      ) : null}

      {inspectedPacket ? (
        <section className="selected-packet" aria-label="Selected packet details">
          <div className="selected-packet-heading">
            <h3>Packet #{inspectedPacket.packetNumber ?? unavailable}</h3>
            <span>{inspectedPacket.protocol || "UNKNOWN"}</span>
          </div>
          <p className="packet-summary">{formatTimestamp(inspectedPacket.timestamp)} | {inspectedPacket.info || unavailable}</p>
          <div className="protocol-tree">
            {getProtocolSections(inspectedPacket).map(([title, fields], index) => (
              <details key={title} open={index < 2}>
                <summary>{title}</summary>
                <dl>
                  {fields.map(([name, value]) => (
                    <div key={name}><dt>{name}</dt><dd>{formatValue(value)}</dd></div>
                  ))}
                </dl>
              </details>
            ))}
          </div>
          <section className="raw-frame" aria-label="Captured raw frame bytes">
            <h4>Raw frame bytes</h4>
            {typeof inspectedPacket.raw?.hex === "string" ? (
              <pre className="hex-viewer"><span className="hex-heading">OFFSET   HEX BYTES                                        ASCII</span>{"\n"}{buildHexRows(inspectedPacket.raw.hex, inspectedPacket.raw.ascii).map((row) => (
                <span className="hex-row" key={row.offset}>{row.offset}  {row.hex}  {row.ascii}{"\n"}</span>
              ))}</pre>
            ) : detailsLoading ? (
              <p>Loading captured frame details...</p>
            ) : detailsError ? (
              <p>{detailsError}</p>
            ) : inspectedPacket.rawStatus === "RAW_BYTES_UNAVAILABLE" ? (
              <p>{inspectedPacket.rawUnavailableReason || "RAW_BYTES_UNAVAILABLE"}</p>
            ) : (
              <p>Raw frame bytes are unavailable.</p>
            )}
          </section>
        </section>
      ) : null}
    </>
  );
};

export default PacketTable;
