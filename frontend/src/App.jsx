const App = () => {
  return (
    <div className="page">
      <header className="header">
        <h1>Real-Time Network Monitoring Dashboard</h1>
        <p>Live packet visibility and alert tracking</p>
      </header>

      <main className="dashboard">
        <section className="card">
          <h2>Live Feed</h2>
          <p>Incoming packet activity will appear here.</p>
        </section>

        <section className="card">
          <h2>Suspicious Alerts</h2>
          <p>Detected alert packets will be listed here.</p>
        </section>

        <section className="card">
          <h2>Traffic Charts</h2>
          <p>Protocol distribution and traffic trends will appear here.</p>
        </section>
      </main>
    </div>
  );
};

export default App;
