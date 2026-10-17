const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const readline = require("readline");
const { randomUUID } = require("crypto");
const { parseCaptureRecord, summarizeCaptureRecord, createPacketSummary } = require("./packetParser");
const { createInvestigationAnalyzer } = require("./investigationAnalyzer");
const PacketLog = require("../models/PacketLog");

const RESTART_DELAY_MS = Number(process.env.SNIFFER_RESTART_DELAY_MS || 2000);
let sharedSnifferService = null;

const createStoragePacket = (packet) => ({
  ...packet,
  raw: packet.raw?.bytes
    ? { bytes: packet.raw.bytes, encoding: packet.raw.encoding }
    : undefined,
  payload: undefined
});

const resolveSnifferCommand = () => {
  const defaultBinary = process.platform === "win32" ? "sniffer-raw.exe" : "sniffer";
  const defaultPath = path.resolve(__dirname, "../../../cpp-sniffer", defaultBinary);
  const configured = process.env.SNIFFER_COMMAND;

  if (!configured || !configured.trim()) {
    return defaultPath;
  }

  const trimmed = configured.trim();
  if (trimmed.toLowerCase().endsWith(".js") || trimmed.toLowerCase().endsWith(".mjs") || trimmed.toLowerCase().endsWith(".cjs")) {
    return process.execPath;
  }

  const resolved = path.isAbsolute(trimmed)
    ? trimmed
    : path.resolve(process.cwd(), trimmed);

  if (
    process.platform === "win32" &&
    path.extname(resolved).toLowerCase() !== ".exe" &&
    fs.existsSync(`${resolved}.exe`)
  ) {
    return `${resolved}.exe`;
  }

  return resolved;
};

const buildSnifferEnvironment = () => {
  const environment = { ...process.env };
  if (process.platform !== "win32") {
    return environment;
  }

  const windowsDirectory = environment.WINDIR || "C:\\Windows";
  const runtimeDirectories = [
    environment.NPCAP_DLL_PATH,
    path.join(windowsDirectory, "System32", "Npcap"),
    path.join(windowsDirectory, "SysWOW64", "Npcap")
  ].filter((directory) => directory && fs.existsSync(directory));
  const currentPath = (environment.PATH || "").split(path.delimiter);
  environment.PATH = [...new Set([...runtimeDirectories, ...currentPath])].join(path.delimiter);
  return environment;
};

const buildSnifferCommandArgs = (selectedInterface) => {
  const configured = (process.env.SNIFFER_COMMAND || "").trim();
  const isScriptInvocation = configured && [".js", ".mjs", ".cjs"].includes(path.extname(configured).toLowerCase());
  const args = [];

  if (isScriptInvocation) {
    const resolved = path.isAbsolute(configured)
      ? configured
      : path.resolve(process.cwd(), configured);
    args.push(resolved);
  }

  if (typeof selectedInterface === "string" && selectedInterface.trim()) {
    args.push(selectedInterface.trim());
  }

  return args;
};

const normalizeInterfaceList = (records = []) => {
  if (!Array.isArray(records)) {
    return [];
  }

  return records
    .filter((record) => record && typeof record === "object")
    .map((record) => ({
      name: typeof record.name === "string" ? record.name : "",
      deviceId: typeof record.deviceId === "string" ? record.deviceId : (typeof record.name === "string" ? record.name : ""),
      friendlyName: typeof record.friendlyName === "string" ? record.friendlyName : (record.description || record.name || "Unknown"),
      description: typeof record.description === "string" ? record.description : "",
      type: typeof record.type === "string" && record.type.trim() ? record.type : "Unknown",
      ipAddresses: Array.isArray(record.ipAddresses) ? record.ipAddresses.filter((value) => typeof value === "string" && value.trim()) : [],
      macAddress: typeof record.macAddress === "string" ? record.macAddress : "",
      status: typeof record.status === "string" ? record.status : "Unknown",
      captureSupported: record.captureSupported !== false && record.captureSupported !== 0,
      captureError: typeof record.captureError === "string" ? record.captureError : ""
    }))
    .filter((record) => record.name || record.deviceId);
};

const createSnifferService = (io) => {
  const command = resolveSnifferCommand();
  let snifferProcess = null;
  let restartTimer = null;
  let findingsTimer = null;
  let lineReader = null;
  let stopRequested = false;
  let packetNumber = 0;
  let previousFindings = "";
  let recordShapeLogged = false;
  let manualStopRequested = false;
  let stopPromise = null;
  let stopTimer = null;
  let resolveStop = null;
  let startInProgress = false;
  let startGeneration = 0;
  const startWaiters = [];
  let captureId = null;
  let activeInterface = null;
  const invalidRecordSignatures = new Set();
  const investigationAnalyzer = createInvestigationAnalyzer();
  const state = {
    status: "Idle",
    selectedInterface: null,
    interfaces: [],
    lastError: null,
    captureId: null,
    packetStats: { received: 0, processed: 0, dropped: 0 }
  };

  const getStatus = () => ({
    ...state,
    selectedInterface: activeInterface || state.selectedInterface,
    captureId: captureId || state.captureId,
    packetStats: { ...state.packetStats }
  });

  const notifyStatus = (statusOverride = null) => {
    const payload = {
      ...getStatus(),
      status: statusOverride || state.status,
      selectedInterface: activeInterface || state.selectedInterface,
      captureId: captureId || state.captureId
    };

    if (io && typeof io.emit === "function") {
      io.emit("capture-status", payload);
    }

    return payload;
  };

  const emitFindings = () => {
    const findings = investigationAnalyzer.getFindings().map((finding) => ({
      ...finding,
      captureId: captureId || state.captureId
    }));
    const update = { ...investigationAnalyzer.getStatus(), findings, captureId: captureId || state.captureId };
    const signature = JSON.stringify(update);

    if (signature !== previousFindings) {
      previousFindings = signature;
      if (io && typeof io.emit === "function") {
        io.emit("investigations", update);
      }
    }
  };

  const setState = (patch = {}) => {
    Object.assign(state, patch);
    if (patch.selectedInterface !== undefined) {
      activeInterface = patch.selectedInterface;
    }
    if (patch.captureId !== undefined) {
      captureId = patch.captureId;
    }
    return getStatus();
  };

  const listInterfaces = async () => {
    let interfaceListProcess;
    try {
      interfaceListProcess = spawn(command, buildSnifferCommandArgs("--list-interfaces"), {
        env: buildSnifferEnvironment(),
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const errorMessage = `Could not start capture provider (${command}): ${error.message}`;
      setState({ status: "Error", lastError: errorMessage, interfaces: [] });
      notifyStatus("Error");
      return [];
    }

    let stdout = "";
    let stderr = "";
    let settled = false;

    return new Promise((resolve) => {
      const fail = (errorMessage) => {
        if (settled) return;
        settled = true;
        setState({ status: "Error", lastError: errorMessage, interfaces: [] });
        notifyStatus("Error");
        resolve([]);
      };

      interfaceListProcess.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });
      interfaceListProcess.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });
      interfaceListProcess.on("error", (error) => {
        fail(`Could not start capture provider (${command}): ${error.message}`);
      });
      interfaceListProcess.on("close", (code) => {
        if (settled) return;
        const trimmed = stdout.trim();
        if (code !== 0) {
          const errorMessage = stderr.trim() || `Capture provider exited with code ${code} while enumerating interfaces.`;
          return fail(errorMessage);
        }
        if (!trimmed) {
          return fail("Capture provider returned no interface data.");
        }

        try {
          const parsed = JSON.parse(trimmed);
          const normalized = normalizeInterfaceList(parsed);
          state.interfaces = normalized;
          state.lastError = normalized.length ? null : "Npcap returned no network devices. Check that the Npcap driver is running and the backend has permission to enumerate adapters.";
          if (!normalized.length) {
            state.status = "Error";
          } else if (!snifferProcess && state.status === "Error") {
            state.status = "Idle";
          }
          if (state.selectedInterface && !normalized.some((item) => item.deviceId === state.selectedInterface || item.name === state.selectedInterface)) {
            state.selectedInterface = null;
            activeInterface = null;
          }
          settled = true;
          notifyStatus(state.status);
          resolve(normalized);
        } catch (error) {
          fail(`Invalid interface list response from capture provider: ${error.message}`);
        }
      });
    });
  };

  const validateInterface = (candidate) => {
    const value = typeof candidate === "string" ? candidate.trim() : "";
    if (!value) {
      return false;
    }

    return state.interfaces.some((item) => {
      const matches = [item.deviceId, item.name]
        .filter((entry) => typeof entry === "string" && entry.trim())
        .map((entry) => entry.trim().toLowerCase());
      const validChoice = matches.includes(value.toLowerCase());
      return validChoice && Boolean(item.captureSupported);
    });
  };

  const stop = () => {
    if (stopPromise) {
      return stopPromise;
    }

    startGeneration += 1;
    stopRequested = true;
    manualStopRequested = true;

    if (restartTimer) {
      clearTimeout(restartTimer);
      restartTimer = null;
    }

    if (findingsTimer) {
      clearInterval(findingsTimer);
      findingsTimer = null;
    }

    stopPromise = (async () => {
      if (startInProgress) {
        await new Promise((resolve) => startWaiters.push(resolve));
      }

      const processToStop = snifferProcess;
      if (!processToStop) {
        setState({ status: "Idle", lastError: null, captureId: null });
        investigationAnalyzer.clear();
        previousFindings = "";
        notifyStatus("Idle");
        emitFindings();
        return { ok: true, status: "Idle" };
      }

      setState({ status: "Stopping", lastError: null });
      notifyStatus("Stopping");

      const stopped = new Promise((resolve) => {
        resolveStop = resolve;
        stopTimer = setTimeout(() => {
          if (snifferProcess === processToStop && !processToStop.killed) {
            processToStop.kill("SIGTERM");
          }
        }, 1000);
      });

      if (processToStop.stdin && !processToStop.stdin.destroyed) {
        processToStop.stdin.write("STOP\n", (error) => {
          if (error && snifferProcess === processToStop && !processToStop.killed) {
            processToStop.kill("SIGTERM");
          }
        });
      } else if (!processToStop.killed) {
        processToStop.kill("SIGTERM");
      }

      return stopped;
    })().finally(() => {
      stopPromise = null;
    });

    return stopPromise;
  };

  const scheduleRestart = () => {
    if (stopRequested || restartTimer || manualStopRequested) {
      return;
    }

    restartTimer = setTimeout(() => {
      restartTimer = null;
      start({ interfaceName: activeInterface || state.selectedInterface || process.env.SNIFFER_INTERFACE || null });
    }, RESTART_DELAY_MS);
  };

  const start = async ({ interfaceName } = {}) => {
    if (stopPromise) {
      await stopPromise;
    }

    if (startInProgress) {
      return { ok: false, error: "Capture startup is already in progress." };
    }

    if (snifferProcess) {
      const error = state.status === "Paused"
        ? "Capture is paused; resume or stop it before starting another session."
        : state.status === "Stopping"
          ? "Capture is still stopping. Wait for it to finish before starting another session."
          : "Capture is already running.";
      return { ok: false, error };
    }

    startInProgress = true;
    const generation = startGeneration;
    try {
      const availableInterfaces = state.interfaces.length ? state.interfaces : await listInterfaces();
      if (generation !== startGeneration) {
        return { ok: false, error: "Capture startup was cancelled because Stop was requested." };
      }

      const requestedInterface = typeof interfaceName === "string" && interfaceName.trim()
        ? interfaceName.trim()
        : (state.selectedInterface || process.env.SNIFFER_INTERFACE || "").trim();
      const interfaceMatch = requestedInterface && availableInterfaces.find((item) =>
        item.deviceId === requestedInterface || item.name === requestedInterface
      );
      if (requestedInterface && !interfaceMatch) {
        const error = `Selected interface "${requestedInterface}" was not found in the current Npcap device list. Refresh interfaces and select a discovered device.`;
        setState({ status: "Error", lastError: error });
        notifyStatus("Error");
        return { ok: false, error };
      }
      const selectedDevice = interfaceMatch || availableInterfaces.find((item) => item.captureSupported);

      if (!selectedDevice || !selectedDevice.name) {
        const error = "No valid capture-capable network interface is available.";
        setState({ status: "Error", lastError: error });
        notifyStatus("Error");
        return { ok: false, error };
      }

      if (!selectedDevice.captureSupported) {
        const error = selectedDevice.captureError || `Npcap could not open interface "${selectedDevice.name}" for capture.`;
        setState({ status: "Error", lastError: error });
        notifyStatus("Error");
        return { ok: false, error };
      }

      stopRequested = false;
      manualStopRequested = false;
      setState({ status: "Starting", lastError: null, selectedInterface: selectedDevice.name, captureId: randomUUID() });
      activeInterface = selectedDevice.name;
      captureId = state.captureId;
      packetNumber = 0;
      state.packetStats = { received: 0, processed: 0, dropped: 0 };
      investigationAnalyzer.clear();
      previousFindings = "";
      invalidRecordSignatures.clear();
      recordShapeLogged = false;

      snifferProcess = spawn(command, buildSnifferCommandArgs(selectedDevice.deviceId || selectedDevice.name), {
        env: buildSnifferEnvironment(),
        stdio: ["pipe", "pipe", "pipe"]
      });
      const processForSession = snifferProcess;
      lineReader = readline.createInterface({ input: processForSession.stdout, crlfDelay: Infinity });

      lineReader.on("line", (line) => {
        if (snifferProcess !== processForSession || stopRequested) return;
        const trimmedLine = line.trim();
        if (!trimmedLine) {
          return;
        }

        let captureRecord;
        try {
          captureRecord = JSON.parse(trimmedLine);
          if (!recordShapeLogged) {
            console.info("Capture record structure:", JSON.stringify(summarizeCaptureRecord(captureRecord)));
            recordShapeLogged = true;
          }
          const packet = {
            ...parseCaptureRecord(captureRecord, packetNumber + 1),
            captureId
          };
          packetNumber += 1;
          state.packetStats.received += 1;
          state.packetStats.processed += 1;
          investigationAnalyzer.ingest(packet);
          if (io && typeof io.emit === "function") {
            io.emit("packet", createPacketSummary(packet));
          }

          PacketLog.create(createStoragePacket(packet)).catch((error) => {
            console.error("Could not save packet log:", error.message);
          });
        } catch (error) {
          const safeSummary = summarizeCaptureRecord(captureRecord);
          const signature = `${error.message}|${safeSummary.availableFields?.join(",") || safeSummary.receivedType}`;
          if (!invalidRecordSignatures.has(signature)) {
            invalidRecordSignatures.add(signature);
            console.error("Invalid capture record:", error.message, JSON.stringify(safeSummary));
          }
        }
      });

      processForSession.stderr.on("data", (chunk) => {
        const text = chunk.toString().trim();
        if (text) {
          console.error("Sniffer stderr:", text);
        }
      });

      processForSession.on("error", (error) => {
        if (snifferProcess !== processForSession) return;
        setState({ status: "Error", lastError: error.message });
        notifyStatus("Error");
        console.error("Failed to start sniffer process:", error.message);
        scheduleRestart();
      });

      processForSession.on("close", (code, signal) => {
        if (lineReader && snifferProcess === processForSession) {
          lineReader.close();
          lineReader = null;
        }

        if (snifferProcess === processForSession && manualStopRequested) {
          snifferProcess = null;
          if (stopTimer) {
            clearTimeout(stopTimer);
            stopTimer = null;
          }
          setState({ status: "Idle", lastError: null, selectedInterface: activeInterface, captureId: null });
          investigationAnalyzer.clear();
          previousFindings = "";
          notifyStatus("Idle");
          emitFindings();
          const resolve = resolveStop;
          resolveStop = null;
          if (resolve) resolve({ ok: true, status: "Idle" });
          return;
        }

        if (snifferProcess === processForSession && !stopRequested) {
          const message = `Sniffer stopped unexpectedly (code=${code}, signal=${signal || "none"}).`;
          setState({ status: "Error", lastError: message, selectedInterface: activeInterface });
          notifyStatus("Error");
          console.error(message);
          scheduleRestart();
        }

        if (snifferProcess === processForSession && stopTimer) {
          clearTimeout(stopTimer);
          stopTimer = null;
        }
        if (snifferProcess === processForSession) snifferProcess = null;
      });

      setState({ status: "Running", lastError: null, selectedInterface: selectedDevice.name, captureId });
      notifyStatus("Running");
      return { ok: true, status: "Running", interfaceName: selectedDevice.name };
    } finally {
      startInProgress = false;
      while (startWaiters.length) startWaiters.shift()();
    }
  };

  const pause = () => {
    if (!snifferProcess || snifferProcess.killed) {
      return { ok: false, error: "There is no active capture process to pause." };
    }

    if (state.status === "Paused") {
      return { ok: true, status: "Paused" };
    }

    if (state.status !== "Running") {
      return { ok: false, error: `Capture is currently ${state.status}.` };
    }

    if (snifferProcess.stdin && !snifferProcess.stdin.destroyed) {
      snifferProcess.stdin.write("PAUSE\n");
    }

    setState({ status: "Paused", lastError: null });
    notifyStatus("Paused");
    return { ok: true, status: "Paused" };
  };

  const resume = () => {
    if (!snifferProcess || snifferProcess.killed) {
      return { ok: false, error: "There is no paused capture process to resume." };
    }

    if (state.status !== "Paused") {
      return { ok: false, error: `Capture is currently ${state.status}.` };
    }

    if (snifferProcess.stdin && !snifferProcess.stdin.destroyed) {
      snifferProcess.stdin.write("RESUME\n");
    }

    setState({ status: "Running", lastError: null });
    notifyStatus("Running");
    return { ok: true, status: "Running" };
  };

  return {
    start,
    pause,
    resume,
    stop,
    listInterfaces,
    validateInterface,
    getStatus,
    getFindings: () => investigationAnalyzer.getFindings().map((finding) => ({ ...finding, captureId: captureId || state.captureId })),
    getInvestigationState: () => ({ ...investigationAnalyzer.getStatus(), captureId: captureId || state.captureId }),
    getProcess: () => snifferProcess
  };
};

const getSharedSnifferService = () => sharedSnifferService;
const setSharedSnifferService = (service) => {
  sharedSnifferService = service;
  return service;
};

module.exports = {
  createSnifferService,
  createStoragePacket,
  getSharedSnifferService,
  setSharedSnifferService
};
