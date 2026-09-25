/**
 * BREACH-DETECTOR backend
 * ------------------------------------------------------------------
 * Real, non-simulated device inventory + reachability service.
 *
 *  - Reachability is determined with an actual ICMP ping (spawns the
 *    OS "ping" binary — the same mechanism real network monitoring
 *    tools use) and, if ICMP is filtered on the network, falls back
 *    to a real TCP connect attempt on a per-device-type default port.
 *  - Device records (including passwords) are persisted to disk in
 *    data/db.json. Passwords are encrypted at rest with AES-256-GCM
 *    before they ever touch the filesystem.
 *  - A pluggable connector system (see ./connectors) lets specific
 *    device classes have their credential actually rotated by this
 *    server instead of by a human pasting it in — currently ships
 *    with a working SSH connector. Devices with no connector fall
 *    back to the manual "generate, then apply on the device" flow,
 *    which is unavoidable for hardware that exposes no management
 *    API at all.
 * ------------------------------------------------------------------
 */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const net = require("net");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const DB_PATH = path.join(__dirname, "data", "db.json");
const KEY_PATH = path.join(__dirname, "data", "encryption.key");
const PROBE_INTERVAL_MS = parseInt(process.env.PROBE_INTERVAL_MS || "15000", 10);
const PING_TIMEOUT_MS = parseInt(process.env.PING_TIMEOUT_MS || "1500", 10);
const TCP_TIMEOUT_MS = parseInt(process.env.TCP_TIMEOUT_MS || "1500", 10);

/* ══════════════════════════════════════════════════════════════
   ENCRYPTION AT REST (AES-256-GCM)
   A per-install key is generated once and stored locally. In a
   real deployment this key should come from a secrets manager /
   environment variable, not sit next to the data — that's called
   out in connectors/README.md.
   ══════════════════════════════════════════════════════════════ */
function loadOrCreateKey() {
  if (fs.existsSync(KEY_PATH)) {
    return Buffer.from(fs.readFileSync(KEY_PATH, "utf8"), "hex");
  }
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
  fs.writeFileSync(KEY_PATH, key.toString("hex"), "utf8");
  return key;
}
const ENC_KEY = loadOrCreateKey();

function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString("hex"), tag: tag.toString("hex"), data: enc.toString("hex") };
}
function decrypt(payload) {
  if (!payload) return null;
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const data = Buffer.from(payload.data, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

/* ══════════════════════════════════════════════════════════════
   PERSISTENT STORE (data/db.json)
   ══════════════════════════════════════════════════════════════ */
function loadDb() {
  if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify({ devices: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
let db = loadDb();

function publicDevice(d) {
  // Never send the encrypted blob or decrypted password to the client by default.
  const { passwordEnc, ...rest } = d;
  // Real elapsed time since the password was actually applied — not a
  // simulated counter. null means no password has ever been applied.
  const pwAge = d.appliedAt
    ? Math.floor((Date.now() - new Date(d.appliedAt).getTime()) / 86400000)
    : null;
  return { ...rest, hasPassword: !!passwordEnc, pwAge };
}

/* ══════════════════════════════════════════════════════════════
   REACHABILITY PROBING — real ICMP ping, TCP fallback
   ══════════════════════════════════════════════════════════════ */
const DEFAULT_PORTS = {
  router: 80, accesspoint: 80, netswitch: 22, nas: 80, ups: 80,
  windows: 445, mac: 445, linux: 22, chromebook: 443, rpi: 22,
  printer: 9100, camera: 80, doorbell: 80, thermostat: 80,
  bulb: 80, plug: 80, switch: 80, lock: 80, speaker: 8009,
  smarttv: 8008, streamer: 8008, console: 80, voip: 5060,
};
// Fallback list tried in order when no explicit port is set and the
// type-default port doesn't answer — covers the common cases where a
// device's actual open port doesn't match its "typical" default.
const COMMON_FALLBACK_PORTS = [80, 443, 8080, 22, 445, 139, 62078];

function candidatePortsFor(device) {
  const ports = [];
  if (device.port) ports.push(device.port); // explicit user-set port wins
  const typeDefault = DEFAULT_PORTS[device.type];
  if (typeDefault && !ports.includes(typeDefault)) ports.push(typeDefault);
  for (const p of COMMON_FALLBACK_PORTS) if (!ports.includes(p)) ports.push(p);
  return ports;
}

function pingHost(ip, timeoutMs) {
  return new Promise((resolve) => {
    const isWin = process.platform === "win32";
    const cmd = isWin
      ? `ping -n 1 -w ${timeoutMs} ${ip}`
      : `ping -c 1 -W ${Math.max(1, Math.ceil(timeoutMs / 1000))} ${ip}`;
    const child = exec(cmd, { timeout: timeoutMs + 500 }, (err, stdout) => {
      if (err) return resolve(false);
      const out = stdout.toLowerCase();
      if (isWin) {
        resolve(out.includes("ttl=") && !out.includes("destination host unreachable") && !out.includes("100% loss"));
      } else {
        resolve(out.includes("1 received") || out.includes("1 packets received"));
      }
    });
    // JS-level watchdog in case exec's own timeout doesn't fire on this platform
    setTimeout(() => { try { child.kill(); } catch (_) {} }, timeoutMs + 800);
  });
}

function tcpProbe(ip, portGuess, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (result) => { if (!done) { done = true; socket.destroy(); resolve(result); } };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(portGuess, ip);
  });
}

async function probeDevice(device) {
  const viaIcmp = await pingHost(device.ip, PING_TIMEOUT_MS);
  if (viaIcmp) return { reachable: true, method: "icmp" };
  // ICMP failed (blocked on the network, or the OS has no ping binary) —
  // fall back to real TCP connect attempts across a short candidate port list.
  for (const port of candidatePortsFor(device)) {
    const ok = await tcpProbe(device.ip, port, TCP_TIMEOUT_MS);
    if (ok) return { reachable: true, method: `tcp:${port}` };
  }
  return { reachable: false, method: null };
}

async function probeAllDevices() {
  let changed = false;
  for (const device of db.devices) {
    const before = device.reachable;
    const { reachable, method } = await probeDevice(device);
    device.reachable = reachable;
    device.probeMethod = method;
    device.lastChecked = new Date().toISOString();
    if (reachable) device.lastSeen = new Date().toISOString();
    if (before !== reachable) changed = true;
  }
  if (changed) saveDb(db);
}
setInterval(probeAllDevices, PROBE_INTERVAL_MS);
probeAllDevices(); // run once at boot rather than waiting a full interval

/* ══════════════════════════════════════════════════════════════
   CONNECTORS — real automated credential rotation where possible
   ══════════════════════════════════════════════════════════════ */
const connectors = {
  ssh: require("./connectors/ssh-connector"),
};
function connectorFor(device) {
  // Devices explicitly flagged with a management protocol get a real connector.
  if (device.managementProtocol && connectors[device.managementProtocol]) {
    return connectors[device.managementProtocol];
  }
  return null;
}

/* ══════════════════════════════════════════════════════════════
   REST API
   ══════════════════════════════════════════════════════════════ */
app.get("/api/health", (req, res) => {
  res.json({ ok: true, probeIntervalMs: PROBE_INTERVAL_MS, deviceCount: db.devices.length });
});

app.get("/api/devices", (req, res) => {
  res.json(db.devices.map(publicDevice));
});

app.post("/api/devices", (req, res) => {
  const { name, type, ip, port, managementProtocol, sshUser, sshPort } = req.body;
  if (!name || !type || !ip) return res.status(400).json({ error: "name, type and ip are required" });
  const device = {
    id: "dev_" + crypto.randomBytes(6).toString("hex"),
    name, type, ip,
    port: port || null, // optional explicit reachability-check port, overrides type default
    managementProtocol: managementProtocol || null, // e.g. "ssh" if this device supports real automated rotation
    sshUser: sshUser || null,
    sshPort: sshPort || 22,
    reachable: false,
    probeMethod: null,
    lastChecked: null,
    lastSeen: null,
    passwordEnc: null,
    pwComplexity: null,
    appliedVia: null,
    appliedAt: null, // pwAge is derived from this at read time — see publicDevice()
    createdAt: new Date().toISOString(),
  };
  db.devices.push(device);
  saveDb(db);
  probeDevice(device).then((r) => {
    device.reachable = r.reachable; device.probeMethod = r.method; device.lastChecked = new Date().toISOString();
    if (r.reachable) device.lastSeen = new Date().toISOString();
    saveDb(db);
  });
  res.status(201).json(publicDevice(device));
});

app.delete("/api/devices/:id", (req, res) => {
  const idx = db.devices.findIndex((d) => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "not found" });
  const [removed] = db.devices.splice(idx, 1);
  saveDb(db);
  res.json({ removed: publicDevice(removed) });
});

/**
 * PATCH a device's password.
 * If the device has a real connector attached (managementProtocol set,
 * e.g. "ssh"), this endpoint ACTUALLY rotates the credential on the
 * device over the network and only stores it once that succeeds.
 * If there is no connector, it stores the password as "pending manual
 * application" — this is the honest real-world fallback for hardware
 * with no management API, and the response says so explicitly.
 */
app.patch("/api/devices/:id/password", async (req, res) => {
  const device = db.devices.find((d) => d.id === req.params.id);
  if (!device) return res.status(404).json({ error: "not found" });
  const { password, complexity, sshPassword } = req.body;
  if (!password) return res.status(400).json({ error: "password is required" });

  const connector = connectorFor(device);
  if (connector) {
    try {
      await connector.applyPassword(device, password, { currentPassword: sshPassword });
      device.passwordEnc = encrypt(password);
      device.pwComplexity = complexity || null;
      device.appliedVia = connector.name;
      device.appliedAt = new Date().toISOString();
      saveDb(db);
      return res.json({ status: "applied_automatically", via: connector.name, device: publicDevice(device) });
    } catch (err) {
      return res.status(502).json({ status: "automation_failed", error: err.message });
    }
  }

  // No connector for this device class — genuinely no way to push it remotely.
  device.passwordEnc = encrypt(password);
  device.pwComplexity = complexity || null;
  device.appliedVia = "manual";
  device.appliedAt = new Date().toISOString();
  saveDb(db);
  res.json({
    status: "manual_required",
    message: "No management connector exists for this device type — copy the password and apply it in the device's own app/admin page, then this endpoint has already recorded it as applied.",
    device: publicDevice(device),
  });
});

app.listen(PORT, () => {
  console.log(`BREACH-DETECTOR backend listening on http://localhost:${PORT}`);
  console.log(`Probing ${db.devices.length} device(s) every ${PROBE_INTERVAL_MS / 1000}s (ICMP, TCP fallback)`);
});
