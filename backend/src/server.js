require("dotenv").config();
const http = require("http");
const { Server } = require("socket.io");
const app = require("./app");
const { connectDatabase } = require("./config/database");
const { createSnifferService, setSharedSnifferService } = require("./services/sniffer");

const PORT = process.env.PORT || 5000;

connectDatabase();

const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*"
  }
});

const snifferService = createSnifferService(io);
setSharedSnifferService(snifferService);

io.on("connection", (socket) => {
  console.log(`Socket client connected: ${socket.id}`);
  socket.emit("investigations", {
    ...snifferService.getInvestigationState(),
    findings: snifferService.getFindings()
  });
  socket.emit("capture-status", snifferService.getStatus());

  socket.on("disconnect", () => {
    console.log(`Socket client disconnected: ${socket.id}`);
  });
});

httpServer.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
});

const shutdown = () => {
  snifferService.stop().finally(() => {
    httpServer.close(() => {
      process.exit(0);
    });
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
