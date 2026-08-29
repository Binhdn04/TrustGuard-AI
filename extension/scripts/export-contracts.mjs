import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve("..");
const virtualEnvironmentPython =
  process.platform === "win32" ? resolve(root, ".venv/Scripts/python.exe") : resolve(root, ".venv/bin/python");
const python = existsSync(virtualEnvironmentPython) ? virtualEnvironmentPython : "python";
const result = spawnSync(
  python,
  [resolve(root, "scripts/export_extension_openapi.py"), "--output", resolve("contracts/openapi-v4.json")],
  { cwd: root, stdio: "inherit" },
);

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
