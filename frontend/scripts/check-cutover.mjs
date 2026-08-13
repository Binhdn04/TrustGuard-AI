import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const sourceRoot = new URL("../src/", import.meta.url);
const allowedCompatibilityFiles = new Set([
  "app/(dashboard)/admin/compatibility/page.tsx",
  "app/(dashboard)/admin/platform/page.tsx",
  "components/admin/compatibility/compatibility-operations.tsx",
  "components/admin/platform-operations.tsx",
  "lib/api/analysis-api.types.ts",
  "lib/api/analysis-api.ts",
  "lib/api/http-analysis-api.ts",
  "lib/api/mock-analysis-api.ts",
]);
const legacySecurityPatterns = [
  /listSourcePolicies/,
  /createSourcePolicy/,
  /listSourceDiscoveries/,
  /decideSourceDiscovery/,
  /getOperationsMetrics/,
  /\/api\/v3\/analyses/,
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
  if (localPath.startsWith("test/") || allowedCompatibilityFiles.has(localPath)) continue;
  const source = await readFile(path, "utf8");
  for (const pattern of legacySecurityPatterns) {
    if (pattern.test(source)) violations.push(`${localPath}: ${pattern}`);
  }
}

if (violations.length > 0) {
  console.error("Legacy fact-check/source-discovery escaped the compatibility boundary:\n" + violations.join("\n"));
  process.exitCode = 1;
} else {
  console.log("Cutover boundary OK: v3 metrics/source discovery are isolated to compatibility files.");
}
