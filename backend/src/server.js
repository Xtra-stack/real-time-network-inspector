require("dotenv").config();
const app = require("./app");
const { connectDatabase } = require("./config/database");
const { startSnifferService } = require("./services/snifferService");

const PORT = process.env.PORT || 5000;

connectDatabase();

app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
  startSnifferService();
});
