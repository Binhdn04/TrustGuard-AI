import { existsSync } from "node:fs";
import { spawn } from "node:child_process";

const serverEntry = ".next/standalone/server.js";
if (!existsSync(serverEntry)) {
  console.error("Missing standalone build. Run `npm run build -- --webpack` and `npm run prepare:standalone` first.");
  process.exit(1);
}

const server = spawn(process.execPath, [serverEntry], {
  cwd: process.cwd(),
  env: { ...process.env, HOSTNAME: "127.0.0.1", PORT: "3000" },
  stdio: "ignore",
});

async function waitForServer() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch("http://127.0.0.1:3000/login");
      if (response.ok) return;
    } catch {
      // The standalone process is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("Standalone frontend did not become ready on port 3000.");
}

try {
  await waitForServer();
  const playwright = spawn(process.execPath, ["node_modules/@playwright/test/cli.js", "test", "--reporter=line"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PLAYWRIGHT_EXTERNAL_SERVER: "1",
      PLAYWRIGHT_PRODUCTION: "1",
    },
    stdio: "inherit",
  });
  const exitCode = await new Promise((resolve, reject) => {
    playwright.once("error", reject);
    playwright.once("exit", (code) => resolve(code ?? 1));
  });
  process.exitCode = exitCode;
} finally {
  server.kill();
}
