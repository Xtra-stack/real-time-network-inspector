# Backend (Step 1)

Basic Express server scaffold for the network monitoring system.

## Run locally

1. Install dependencies:
   npm install
2. Copy `.env.example` to `.env` and update values if needed.
3. Start development server:
   npm run dev

## Available endpoint

- GET /api/health

## Sniffer service

On startup, the backend starts the C++ sniffer process and reads packet lines from stdout.
Each line is parsed as JSON and logged to the console.

Environment variables:

- SNIFFER_COMMAND (default: `../cpp-sniffer/sniffer`)
- SNIFFER_INTERFACE (default: `eth0`)
