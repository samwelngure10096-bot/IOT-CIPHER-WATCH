# Connectors — why some devices auto-rotate and most don't

This is the honest core of the "can we automate pasting the password"
question. There is no universal API across IoT hardware. What real
security/asset-management platforms do — and what BREACH-DETECTOR does
— is a **connector per management protocol**, applied only to the
device classes that actually expose one.

## Shipped in this build

- **`ssh-connector.js`** — real, working. Opens an actual SSH session
  (via the `ssh2` library) to the device using its current
  credentials, and runs `chpasswd` on the remote shell. Applies to:
  Linux servers, Raspberry Pi, and OpenWrt/DD-WRT-based routers with
  SSH enabled.

## Not shipped, but real and addable the same way

| Device class | Real protocol/API | Effort to add |
|---|---|---|
| MikroTik routers | RouterOS REST/SSH API | Low — same shape as ssh-connector |
| Ubiquiti UniFi gear | UniFi Controller API (token auth) | Low |
| Philips Hue | Hue Bridge local API (auth token) | Low |
| TP-Link Kasa | Kasa cloud API or local TCP protocol | Medium |
| ONVIF IP cameras | ONVIF device management (SOAP) | Medium |
| Windows PCs on a domain | PowerShell remoting / WinRM | Medium |

Each of these would be a new file in this folder exporting
`{ name, applyPassword(device, newPassword, opts) }`, then registered
in `server.js`'s `connectors` map and set on a device via
`managementProtocol`.

## Why the rest genuinely can't be automated

A large share of consumer IoT — cheap smart bulbs, plugs, sensors,
baby monitors, most budget cameras — expose **no local network API at
all**. Their only interface is a proprietary mobile app talking to the
vendor's cloud. There is nothing on the LAN for any dashboard,
including this one, to call. For those, `PATCH /api/devices/:id/password`
correctly returns `status: "manual_required"` — the password is
generated and recorded, and the human applies it in the vendor app.
This is not a shortcut we're choosing to skip; it's the real
architecture of those devices.
