import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const sourceRoot = new URL("../src/", import.meta.url);
const legacySecurityPatterns = [
  /listSourcePolicies/,
  /createSourcePolicy/,
  /listSourceDiscoveries/,
  /decideSourceDiscovery/,
  /getOperationsMetrics/,
  /\/api\/v3\/analyses/,
  /\/api\/v2/,
  /\/api\/v3\/admin\/actions/,
];

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return [".ts", ".tsx"].includes(extname(entry.name)) ? [path] : [];
  }));
  return nested.flat();
}

const rootPath = sourceRoot.pathname.replace(/^\/(.:\/)/, "$1");
const violations = [];
for (const path of await sourceFiles(rootPath)) {
  const localPath = relative(rootPath, path).replaceAll("\\", "/");
  if (localPath.startsWith("test/")) continue;
  const source = await readFile(path, "utf8");
  for (const pattern of legacySecurityPatterns) {
    if (pattern.test(source)) violations.push(`${localPath}: ${pattern}`);
  }
}

if (violations.length > 0) {
  console.error("Legacy v2/v3 API usage remains in the frontend:\n" + violations.join("\n"));
  process.exitCode = 1;
} else {
  console.log("Cutover boundary OK: frontend uses only the v4 product API.");
}
