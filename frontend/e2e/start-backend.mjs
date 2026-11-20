import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..");
const backendDir = path.join(repoRoot, "backend");

const pyWin = path.join(backendDir, ".venv", "Scripts", "python.exe");
const pyUnix = path.join(backendDir, ".venv", "bin", "python");
const pythonBin = fs.existsSync(pyWin) ? pyWin : fs.existsSync(pyUnix) ? pyUnix : "python";

const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "chaoslab-e2e-"));
const dbPath = path.join(runDir, "chaoslab-e2e.db").replace(/\\/g, "/");

const env = {
  ...process.env,
  CHAOSLAB_ENV: "development",
  CHAOSLAB_DATABASE_URL: `sqlite:///${dbPath}`,
  CHAOSLAB_SECRET_KEY: "e2e-only-test-secret-key-not-for-prod-use",
  CHAOSLAB_COOKIE_SECURE: "false",
  CHAOSLAB_CORS_ORIGINS: '["http://127.0.0.1:5174","http://localhost:5174"]',
};

execFileSync(pythonBin, ["-m", "chaoslab", "init-db"], { cwd: backendDir, env, stdio: "inherit" });
execFileSync(pythonBin, ["-m", "chaoslab", "seed-demo"], { cwd: backendDir, env, stdio: "inherit" });

const child = spawn(
  pythonBin,
  [
    "-m",
    "uvicorn",
    "chaoslab.api.app:get_asgi_app",
    "--factory",
    "--host",
    "127.0.0.1",
    "--port",
    "8011",
  ],
  { cwd: backendDir, env, stdio: "inherit" }
);

function shutdown() {
  if (!child.killed) {
    child.kill("SIGTERM");
  }
  try {
    fs.rmSync(runDir, { recursive: true, force: true });
  } catch {
    // Ignore Windows locked temp file cleanup errors on teardown
  }
}

process.on("SIGINT", () => {
  shutdown();
  process.exit(0);
});
process.on("SIGTERM", () => {
  shutdown();
  process.exit(0);
});
process.on("exit", shutdown);

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
