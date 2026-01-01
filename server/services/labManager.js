// Minimal fire-and-forget lab launcher (no proxy management)
const { spawn } = require("child_process");
const path = require("path");

const LAB_ROOT = path.join(__dirname, "..", "..", "ngn-sdn-firewall");
const KATHARA_BIN = process.env.KATHARA_BIN || "kathara";
let busy = false;

function runBackground(args) {
  const proc = spawn(KATHARA_BIN, args, {
    cwd: LAB_ROOT,
    env: { ...process.env, KATHARA_NON_INTERACTIVE: "1" },
    stdio: "ignore",
    detached: true,
  });
  proc.unref();
  proc.on("error", (err) => console.error("Kathara command error", err));
  proc.on("close", (code) => {
    if (code !== 0) console.error(`Kathara ${args.join(" ")} exited with code ${code}`);
  });
}

function startLab() {
  if (busy) return { ok: false, error: "busy" };
  busy = true;
  try {
    runBackground(["lstart", "--noterminals"]);
    return { ok: true };
  } catch (err) {
    console.error("Start lab failed", err);
    return { ok: false, error: err.message || String(err) };
  } finally {
    setTimeout(() => { busy = false; }, 500);
  }
}

function stopLab() {
  if (busy) return { ok: false, error: "busy" };
  busy = true;
  try {
    runBackground(["lclean"]);
    return { ok: true };
  } catch (err) {
    console.error("Stop lab failed", err);
    return { ok: false, error: err.message || String(err) };
  } finally {
    setTimeout(() => { busy = false; }, 500);
  }
}

module.exports = { startLab, stopLab };
