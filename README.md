# Real-Time Network Inspector

A beginner-friendly, full-stack network monitoring project that captures live packets, analyzes traffic, stores logs, and visualizes everything in a real-time dashboard.

## Project Overview

This project is built to demonstrate practical networking and full-stack development in one system:

- A C++ sniffer captures live packets from a selected network interface.
- A Node.js backend runs the sniffer, analyzes packets, stores logs, and provides APIs.
- A React frontend shows live traffic, alerts, and charts.

The design goal is simple and readable implementation over complex architecture.

## Tech Stack

- C++ (libpcap / Npcap)
- Node.js + Express
- Socket.io
- MongoDB + Mongoose
- React + Vite
- Recharts

## Architecture

The project is split into 3 modules:

### 1) C++ Sniffer

Location: cpp-sniffer/

Responsibilities:

- Capture packets from a network interface.
- Extract source IP, destination IP, protocol, and timestamp.
- Print one JSON packet per line to standard output.

### 2) Backend API + Real-Time Server

Location: backend/

Responsibilities:

- Run the compiled C++ sniffer using child_process.
- Read sniffer stdout line by line.
- Parse and analyze packet data.
- Detect protocol type (HTTP, DNS, TCP, UDP).
- Flag suspicious packets using keyword matching.
- Store packet logs in MongoDB.
- Expose REST APIs.
- Emit real-time packet updates via Socket.io.

### 3) Frontend Dashboard

Location: frontend/

Responsibilities:

- Fetch initial packet data from REST APIs.
- Receive live packet updates from Socket.io.
- Show latest packet feed and suspicious alerts.
- Visualize protocol distribution and traffic-over-time charts.

## Features

- Live packet capture from system interface.
- JSON-based packet stream from sniffer.
- Packet analysis and alert detection.
- Persistent packet logging in MongoDB.
- REST APIs for packets, alerts, and stats.
- Real-time packet broadcasting with Socket.io.
- Dashboard with:
  - latest live packets
  - highlighted suspicious packets
  - protocol distribution pie chart
  - traffic-over-time line chart

## API Endpoints

Base URL: http://localhost:5000/api

- GET /health
- GET /packets
- GET /alerts
- GET /stats

## Setup Instructions

## Prerequisites

- Node.js 18+
- MongoDB running locally (or a MongoDB URI)
- C++ compiler
- libpcap (Linux/macOS) or Npcap + developer libs (Windows)

## 1) Build C++ Sniffer

Open a terminal in cpp-sniffer/.

Linux:

```bash
g++ main.cpp -lpcap -o sniffer
```

Windows (Developer Command Prompt):

```bash
cl /EHsc main.cpp wpcap.lib Ws2_32.lib
```

## 2) Configure Backend

1. Open backend/.
2. Copy .env.example to .env.
3. Update values if needed.

Example .env:

```env
PORT=5000
MONGODB_URI=mongodb://127.0.0.1:27017/network_inspector
SNIFFER_COMMAND=../cpp-sniffer/sniffer
SNIFFER_INTERFACE=eth0
```

## 3) Install and Run Backend

```bash
cd backend
npm install
npm run dev
```

## 4) Install and Run Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the frontend URL shown by Vite (usually http://localhost:5173).

## How It Works (Data Flow)

1. C++ sniffer captures packets and prints JSON lines.
2. Backend starts the sniffer process and reads stdout stream.
3. Each packet is parsed and analyzed.
4. Backend stores analyzed packets in MongoDB.
5. Backend exposes historical data through REST APIs.
6. Frontend loads initial packets and alerts using /packets and /alerts.
7. Backend emits each new analyzed packet over Socket.io.
8. Frontend receives live packet events and updates UI instantly.

## Project Structure

```text
.
|-- backend/
|   |-- src/
|   |   |-- config/
|   |   |-- controllers/
|   |   |-- models/
|   |   |-- routes/
|   |   `-- services/
|   `-- .env.example
|-- cpp-sniffer/
|   `-- main.cpp
`-- frontend/
    `-- src/
        |-- components/
        `-- App.jsx
```

## Future Improvements

- Add authentication for dashboard access.
- Add packet filtering (protocol, IP, time range).
- Add pagination for packet history APIs.
- Improve suspicious detection with rule sets.
- Add unit/integration tests.
- Add Docker setup for easier deployment.
- Add deployment config for cloud hosting.

## Notes

- This project is intended for learning and monitoring your own network environment.
- Run packet capture with proper permissions.
