# Backend (Step 1)

Basic Express server scaffold for the network monitoring system.

## Run locally

1. Install dependencies:
   npm install
2. Copy `.env.example` to `.env` and update values if needed.
3. Start development server:
   npm run dev

## Available endpoints

- GET /api/health
- GET /api/packets
- GET /api/alerts
- GET /api/stats

## Sniffer service

On startup, the backend starts the C++ sniffer process and reads packet lines from stdout.
Each line is parsed as JSON, analyzed, and then stored in MongoDB packet logs.

## Real-time updates

Socket.io is attached to the backend server.
Whenever a packet is captured and analyzed, the backend emits a `packet` event
with the full analyzed packet object.

### Quick test client

You can verify real-time events with a tiny Node.js client.

1. Install client package:
    npm install socket.io-client
2. Create a file like `socket-test.js`:

```js
const { io } = require("socket.io-client");

const socket = io("http://localhost:5000");

socket.on("connect", () => {
   console.log("Connected:", socket.id);
});

socket.on("packet", (packet) => {
   console.log("Live packet:", packet);
});
```

3. Run it:
    node socket-test.js

Environment variables:

- MONGODB_URI (default local example in `.env.example`)
- SNIFFER_COMMAND (default: `../cpp-sniffer/sniffer`)
- SNIFFER_INTERFACE (default: `eth0`)
