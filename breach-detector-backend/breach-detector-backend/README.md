# BREACH-DETECTOR backend

A real (not simulated) Node.js/Express service that:

1. **Probes every registered device for reachability** using an actual
   ICMP ping (spawns the OS `ping` binary), falling back to real TCP
   connect attempts across a short list of candidate ports if ICMP is
   unavailable or blocked. Runs on an interval (default every 15s) and
   also once immediately when a device is added.
2. **Persists devices to disk** in `data/db.json`, with device
   passwords encrypted at rest using AES-256-GCM (`data/encryption.key`
   is generated on first run — keep it safe, back it up, and in a real
   deployment move it into a secrets manager rather than leaving it on
   disk next to the data).
3. **Actually rotates credentials where a real management protocol
   exists** (currently SSH — see `connectors/README.md`), and honestly
   falls back to "generate it, human applies it" for devices with no
   such API — which is most consumer IoT.

## Setup

```bash
npm install
cp .env.example .env     # adjust PORT / timeouts if you want
npm start
```

The server listens on `http://localhost:4000` by default. Point the
BREACH-DETECTOR frontend's `apiHost` constant at wherever this runs
(same machine: `http://localhost:4000`; another machine on your LAN:
`http://<that machine's IP>:4000`).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness + probe interval + device count |
| GET | `/api/devices` | List all devices with real reachability status |
| POST | `/api/devices` | Register a device — `{ name, type, ip, port?, managementProtocol?, sshUser?, sshPort? }` |
| DELETE | `/api/devices/:id` | Permanently remove a device |
| PATCH | `/api/devices/:id/password` | Rotate a password — automatically via a connector if `managementProtocol` is set, otherwise records it as pending manual application |

## Verified working (see project chat log for the actual test run)

- TCP reachability correctly returns `true` for a genuinely open port
  and `false` for a genuinely closed one.
- A device with no connector correctly returns `manual_required`.
- A device configured with `managementProtocol: "ssh"` genuinely
  attempts a real SSH connection — tested against an address with
  nothing listening, and it failed with a real network-level error
  (`EHOSTUNREACH`), proving it isn't a stub that always reports success.

## Known limitation to sanity-check on your own network

ICMP ping requires the `ping` binary to exist on whatever machine runs
this backend (present by default on Windows, macOS, and virtually all
desktop/server Linux — just not in the minimal container this was
developed in). If `ping` is missing, the code automatically falls back
to TCP probing, so reachability detection still works — it just relies
on the fallback until ICMP is available. Do one real test against a
device you know is powered on vs one you know is off, on your actual
LAN, before relying on it for a demo.

## Wiring in the encrypted-store / MongoDB version

This build uses an encrypted JSON file (`data/db.json`) so it runs
with zero external services. If your earlier design used MongoDB with
AES-256-GCM, swapping the `loadDb`/`saveDb` functions in `server.js`
for Mongoose calls is a drop-in change — the encryption helpers,
probing engine, and connector system don't need to change at all.
