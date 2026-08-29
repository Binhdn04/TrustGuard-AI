import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const temporaryDirectory = await mkdtemp(join(tmpdir(), "trustguard-extension-contract-"));
const generatedPath = join(temporaryDirectory, "v4.generated.ts");
const cli = resolve("node_modules/openapi-typescript/bin/cli.js");

try {
  const result = spawnSync(process.execPath, [cli, resolve("contracts/openapi-v4.json"), "-o", generatedPath], {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);

  const [expected, generated] = await Promise.all([
    readFile(resolve("src/contracts/v4.generated.ts"), "utf8"),
    readFile(generatedPath, "utf8"),
  ]);
  if (generated !== expected) {
    throw new Error("Generated v4 TypeScript contract drifted. Run npm run contracts:generate and review the diff.");
  }
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
