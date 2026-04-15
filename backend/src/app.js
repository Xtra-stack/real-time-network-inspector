const express = require("express");
const cors = require("cors");
const packetRoutes = require("./routes");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api", packetRoutes);

module.exports = app;
