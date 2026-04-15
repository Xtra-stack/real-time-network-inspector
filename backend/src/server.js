require("dotenv").config();
const http = require("http");
const { Server } = require("socket.io");
const app = require("./app");
const { connectDatabase } = require("./config/database");
const { startSnifferService } = require("./services/snifferService");

const PORT = process.env.PORT || 5000;

connectDatabase();

const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*"
  }
});

io.on("connection", (socket) => {
  console.log(`Socket client connected: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log(`Socket client disconnected: ${socket.id}`);
  });
});

httpServer.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
  startSnifferService(io);
});
