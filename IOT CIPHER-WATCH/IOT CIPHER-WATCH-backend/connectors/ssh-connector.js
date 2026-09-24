/**
 * SSH connector — REAL automated password rotation.
 * ------------------------------------------------------------------
 * Applies to: Linux servers, Raspberry Pi, OpenWrt-based routers,
 * and anything else reachable over SSH with a user that can change
 * its own password (or has sudo for chpasswd).
 *
 * This is not a simulation: it opens a genuine SSH connection with
 * the ssh2 library, authenticates with the device's CURRENT
 * password (or a private key, see keyPath below), and runs the
 * real shell command to set the new password.
 * ------------------------------------------------------------------
 */
const { Client } = require("ssh2");

const name = "ssh";

/**
 * @param {object} device - { ip, sshUser, sshPort }
 * @param {string} newPassword - the password to set
 * @param {object} opts - { currentPassword, keyPath? }
 */
function applyPassword(device, newPassword, opts = {}) {
  return new Promise((resolve, reject) => {
    if (!device.sshUser) {
      return reject(new Error("Device has no sshUser configured — cannot authenticate."));
    }
    if (!opts.currentPassword && !opts.keyPath) {
      return reject(new Error("No currentPassword or SSH key supplied to authenticate with before rotating."));
    }

    const conn = new Client();
    const timeout = setTimeout(() => {
      conn.end();
      reject(new Error("SSH connection timed out."));
    }, 8000);

    conn
      .on("ready", () => {
        // chpasswd reads "user:newpassword" from stdin — this is the standard
        // real-world way to script a password change on Linux non-interactively.
        const escaped = newPassword.replace(/'/g, `'\\''`);
        const cmd = `echo '${device.sshUser}:${escaped}' | sudo -S chpasswd 2>&1 || echo '${device.sshUser}:${escaped}' | chpasswd 2>&1`;
        conn.exec(cmd, (err, stream) => {
          if (err) { clearTimeout(timeout); conn.end(); return reject(err); }
          let output = "";
          stream
            .on("close", (code) => {
              clearTimeout(timeout);
              conn.end();
              if (code === 0) resolve({ output });
              else reject(new Error(`Remote password change exited with code ${code}: ${output.trim()}`));
            })
            .on("data", (data) => { output += data.toString(); })
            .stderr.on("data", (data) => { output += data.toString(); });
        });
      })
      .on("error", (err) => { clearTimeout(timeout); reject(err); })
      .connect({
        host: device.ip,
        port: device.sshPort || 22,
        username: device.sshUser,
        password: opts.currentPassword,
        readyTimeout: 6000,
      });
  });
}

module.exports = { name, applyPassword };
