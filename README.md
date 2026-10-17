# Network Packet Inspector

A real-time network packet inspection platform built for authorized monitoring and debugging. The project combines a native C++ capture provider, a Node.js backend, and a React dashboard to collect live traffic, decode packets, and surface suspicious or high-priority activity.

This project is designed to be practical and readable rather than over-engineered. The capture path is real, the packet bytes are preserved, and the UI works from actual Npcap/libpcap data rather than fabricated summaries.

## What this project does

- Enumerates live network interfaces on Windows via Npcap
- Lets the user select an adapter and control capture state
- Starts, pauses, resumes, and stops capture sessions cleanly
- Preserves the original captured frame bytes for each packet
- Decodes common protocols such as Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, and DNS
- Displays live packet tables, per-packet details, and hex/ASCII views
- Stores capture data and basic stats for lookup and inspection
- Provides a dashboard for live monitoring and packet investigation

## Architecture

- C++ capture provider: `cpp-sniffer/main.cpp`
  - Uses libpcap/Npcap to open a selected interface
  - Captures raw frames and emits JSON records with metadata and base64 frame bytes
  - Exposes interface discovery and lifecycle control from the Node layer

- Node.js backend: `backend/src/`
  - Starts and manages the native sniffer process
  - Validates interfaces and capture lifecycle state
  - Parses capture records and normalizes packet objects
  - Exposes REST APIs and Socket.IO events for the dashboard
  - Stores packet logs and related analysis data when MongoDB is configured

- React frontend: `frontend/src/`
  - Selects an interface and control buttons for Start, Pause, Resume, and Stop
  - Streams packet updates in real time
  - Displays packet lists, protocol details, and byte-level views

## Important technical rule

This project does not reconstruct raw bytes from IP addresses or protocol labels. The raw frame is captured from the native library and preserved as-is. If the provider does not emit the original frame bytes, the UI cannot display the actual packet data reliably.

The fix was to repair the capture source so it sends real packet bytes instead of metadata-only summaries.

## Current verified capture flow

The working flow is:

1. The native capture provider enumerates adapters and returns real Npcap device IDs.
2. Node selects the chosen interface and launches the child capture process.
3. Each packet is emitted as a JSON record containing:
   - timestamp
   - interface metadata
   - capture length and original length
   - datalink information
   - base64-encoded raw frame bytes
4. The backend parses and normalizes the packet and sends it through Socket.IO.
5. The frontend loads packet details on demand from the selected packet ID and renders the full record.

## Capture lifecycle

The system supports the following states:

- Idle
- Starting
- Running
- Paused
- Stopping

The lifecycle logic is designed to return cleanly to Idle after Stop so the user can start a new capture session immediately. This includes resetting the current capture state and clearing per-session timers before the next run.

## Project structure

```text
README.md
backend/
  package.json
  src/
    app.js
    server.js
    routes/
    controllers/
    services/
    models/
  test/
cpp-sniffer/
  main.cpp
  README.md
frontend/
  package.json
  src/
```

## Setup

### Prerequisites

- Node.js 18+
- A C++ toolchain compatible with your platform
- Npcap installed on Windows for live packet capture
- Optional: MongoDB if you want persisted packet history

### Windows capture setup

1. Install Npcap and ensure the driver is running.
2. Confirm the adapter you want to use is available in the capture provider output.
3. Build or rebuild the C++ sniffer against the local Npcap SDK and runtime setup.
4. Ensure the sniffer binary can resolve its required DLLs when spawned by Node.

### Backend

```bash
cd backend
npm install
npm start
```

The backend normally listens on port 5000.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite in the terminal, usually http://localhost:5173.

## API endpoints

Base URL: http://localhost:5000

- GET /api/health
- GET /api/capture/interfaces
- GET /api/capture/status
- POST /api/capture/start
- POST /api/capture/pause
- POST /api/capture/resume
- POST /api/capture/stop
- GET /api/packets
- GET /api/packets/:captureId/:packetNumber
- GET /api/stats
- GET /api/alerts

## Real-time events

The backend emits Socket.IO events for live packet updates and analysis status. The frontend uses these events to update the packet list without reloading the page.

## Verification status

The project has been validated in the current workspace with real adapter discovery and lifecycle checks:

- Real Npcap interfaces were enumerated successfully
- Capture start, pause, resume, and stop transitions were tested
- Same-interface and different-interface restart flows were validated
- Backend test suite: 35 passed
- Frontend test suite: 1 passed
- Production frontend build: succeeded

## Notes for use

- Only capture traffic you are authorized to inspect.
- Do not treat the UI as proof of malicious activity without validating the packet content.
- A valid capture provider is required before packet decoding can be trusted.
- When the packet engine does not emit raw bytes, the correct fix is to repair the capture source, not to invent data from metadata.

## Commit and iteration guidance

This project is meant to be built incrementally and kept understandable. Prefer small, meaningful changes and verify them before moving on. When you complete a feature, commit with a clear message that reflects the actual behavior added or fixed.

