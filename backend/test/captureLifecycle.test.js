const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createSnifferService } = require("../src/services/sniffer");

const fakeSnifferScript = path.join(os.tmpdir(), `fake-sniffer-${process.pid}.js`);
const originalCommand = process.env.SNIFFER_COMMAND;

fs.writeFileSync(fakeSnifferScript, `
const fs = require('fs');
const arg = process.argv[2] || '';
if (arg === '--list-interfaces') {
  const interfaces = [
    { name: '\\\\Device\\\\NPF_{WIFI}', deviceId: '\\\\Device\\\\NPF_{WIFI}', friendlyName: 'Intel Wi-Fi adapter', description: 'Intel Wi-Fi adapter', type: 'Wi-Fi', ipAddresses: ['192.168.1.50'], macAddress: '00:11:22:33:44:55', status: 'Up', captureSupported: true },
    { name: '\\\\Device\\\\NPF_Loopback', deviceId: '\\\\Device\\\\NPF_Loopback', friendlyName: 'Microsoft Loopback', description: 'Microsoft Loopback', type: 'Loopback', ipAddresses: ['127.0.0.1'], macAddress: '00:00:00:00:00:00', status: 'Up', captureSupported: true },
    { name: '\\\\Device\\\\NPF_{BLUETOOTH}', deviceId: '\\\\Device\\\\NPF_{BLUETOOTH}', friendlyName: 'Bluetooth HCI', description: 'Bluetooth HCI', type: 'Bluetooth', ipAddresses: [], macAddress: '00:00:00:00:00:00', status: 'Up', captureSupported: false, captureError: 'Adapter cannot be opened for packet capture.' }
  ];
  process.stdout.write(JSON.stringify(interfaces));
  process.exit(0);
}

let paused = false;
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  const text = chunk.toString();
  if (text.includes('PAUSE')) paused = true;
  if (text.includes('RESUME')) paused = false;
  if (text.includes('STOP')) process.exit(0);
});

process.stdout.write(JSON.stringify({ ok: true, interface: arg, paused }));
process.stdout.write("\\n");
setInterval(() => {
  if (!paused) {
    process.stdout.write(JSON.stringify({ ok: true, interface: arg, tick: Date.now() }));
    process.stdout.write("\\n");
  }
}, 50);
`);

const makeService = () => createSnifferService({
  emit: () => {}
});

test.before(() => {
  process.env.SNIFFER_COMMAND = fakeSnifferScript;
});

test.after(() => {
  if (originalCommand === undefined) {
    delete process.env.SNIFFER_COMMAND;
  } else {
    process.env.SNIFFER_COMMAND = originalCommand;
  }
  fs.unlinkSync(fakeSnifferScript);
});

test("discovers interfaces and rejects invalid interface names", async () => {
  const service = makeService();
  const interfaces = await service.listInterfaces();

  assert.equal(Array.isArray(interfaces), true);
  assert.equal(interfaces.length >= 2, true);
  assert.equal(interfaces[0].friendlyName, "Intel Wi-Fi adapter");
  assert.equal(service.validateInterface("\\Device\\NPF_{WIFI}"), true);
  assert.equal(service.validateInterface("Intel Wi-Fi adapter"), false);
  assert.equal(service.validateInterface("Missing Interface"), false);
  const invalidStart = await service.start({ interfaceName: "Intel Wi-Fi adapter" });
  assert.equal(invalidStart.ok, false);
  assert.match(invalidStart.error, /not found in the current Npcap device list/);
});

test("supports pause, resume, and stop-start on the same and a different interface", async () => {
  const service = makeService();
  const interfaces = await service.listInterfaces();
  const interfaceName = interfaces[0].deviceId;
  const otherInterfaceName = interfaces[1].deviceId;

  const startResult = await service.start({ interfaceName });
  assert.equal(startResult.ok, true);
  assert.equal(service.getStatus().status, "Running");
  const firstProcess = service.getProcess();
  const firstCaptureId = service.getStatus().captureId;

  const pauseResult = service.pause();
  assert.equal(pauseResult.ok, true);
  assert.equal(service.getStatus().status, "Paused");

  const resumeResult = service.resume();
  assert.equal(resumeResult.ok, true);
  assert.equal(service.getStatus().status, "Running");

  const stopResult = await service.stop();
  assert.equal(stopResult.ok, true);
  assert.equal(stopResult.status, "Idle");
  assert.equal(service.getStatus().status, "Idle");
  assert.equal(service.getProcess(), null);

  const sameInterfaceRestart = await service.start({ interfaceName });
  assert.equal(sameInterfaceRestart.ok, true);
  assert.equal(service.getStatus().selectedInterface, interfaceName);
  assert.notEqual(service.getStatus().captureId, firstCaptureId);
  assert.notEqual(service.getProcess(), firstProcess);

  const secondProcess = service.getProcess();
  const sameInterfaceStop = await service.stop();
  assert.equal(sameInterfaceStop.status, "Idle");
  assert.equal(service.getProcess(), null);

  const differentInterfaceRestart = await service.start({ interfaceName: otherInterfaceName });
  assert.equal(differentInterfaceRestart.ok, true);
  assert.equal(service.getStatus().selectedInterface, otherInterfaceName);
  assert.notEqual(service.getProcess(), secondProcess);
  const differentInterfaceStop = await service.stop();
  assert.equal(differentInterfaceStop.status, "Idle");
  assert.equal(service.getStatus().status, "Idle");
  assert.equal(service.getProcess(), null);
});

test("unsupported Bluetooth interfaces remain labeled as unsupported for capture", async () => {
  const service = makeService();
  const interfaces = await service.listInterfaces();
  const bluetooth = interfaces.find((device) => device.type === "Bluetooth");

  assert.equal(Boolean(bluetooth), true);
  assert.equal(bluetooth.captureSupported, false);
  assert.equal(service.validateInterface(bluetooth.deviceId), false);
});
