const { createSnifferService } = require("./sniffer");

const startSnifferService = (io) => {
  const service = createSnifferService(io);
  service.start();
  return service;
};

module.exports = {
  startSnifferService
};
