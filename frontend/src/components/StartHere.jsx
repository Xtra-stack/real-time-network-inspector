const StartHere = ({ findings, status, statusMessage, decodedTcpPackets, onInvestigate }) => (
  <section className="card start-here-card">
    <div className="card-head">
      <div>
        <p className="section-kicker">INVESTIGATION PRIORITY</p>
        <h2>Start Here</h2>
      </div>
      <span className="card-meta">Ranked from observed packet evidence</span>
    </div>

    {status !== "ready" ? (
      <p className="findings-empty">{statusMessage || "Insufficient packet metadata to evaluate TCP handshake failures."}</p>
    ) : !findings.length ? (
      <p className="findings-empty">
        No prioritized TCP handshake failures observed among {decodedTcpPackets} decoded TCP packets.
      </p>
    ) : (
      <ol className="finding-list">
        {findings.map((finding) => (
          <li className="finding-item" key={finding.id}>
            <div className="finding-priority-wrap">
              <span className={`finding-priority priority-${finding.priority.toLowerCase()}`}>
                {finding.priority}
              </span>
              <span className="finding-score">Score {finding.priorityScore}</span>
            </div>
            <div className="finding-content">
              <h3>{finding.title}</h3>
              <p className="finding-summary">
                {finding.affectedPackets} packets | {finding.affectedFlows} flows | {finding.affectedHosts} source hosts
              </p>
              <p className="finding-route">{finding.source} <span aria-hidden="true">-&gt;</span> {finding.destination}</p>
              <p className="finding-evidence">{finding.observed} {finding.evidence[1]}</p>
              <p className="finding-next-step"><strong>Next:</strong> {finding.recommendedNextStep}</p>
            </div>
            <button className="finding-action" type="button" onClick={() => onInvestigate(finding)}>
              Investigate packets
            </button>
          </li>
        ))}
      </ol>
    )}
  </section>
);

export default StartHere;