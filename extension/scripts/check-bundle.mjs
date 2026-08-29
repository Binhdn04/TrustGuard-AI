import { readdir, readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";

const dist = resolve("dist");
const inspectedExtensions = new Set([".css", ".html", ".js", ".json"]);
const forbidden = [
  { label: "embedded client secret", pattern: /client[_-]?secret/i },
  { label: "remote dynamic import", pattern: /\bimport\s*\(\s*["'`]https?:\/\//i },
  { label: "remote imported script", pattern: /\bimportScripts\s*\(\s*["'`]https?:\/\//i },
  { label: "remote executable HTML", pattern: /<(?:script|link)[^>]+(?:src|href)=["']https?:\/\//i },
  { label: "WebSocket construction", pattern: /new\s+WebSocket\s*\(/i },
  { label: "EventSource construction", pattern: /new\s+EventSource\s*\(/i },
  { label: "XMLHttpRequest construction", pattern: /new\s+XMLHttpRequest\s*\(/i },
  { label: "dynamic eval", pattern: /\beval\s*\(/ },
  { label: "dynamic Function constructor", pattern: /new\s+Function\s*\(/ },
  { label: "source map reference", pattern: /sourceMappingURL/i },
  { label: "demo token", pattern: /demo[-_ ]?token/i },
  { label: "bearer credential", pattern: /bearer\s+[a-z0-9._~-]{8,}/i },
];

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else files.push(path);
  }
  return files;
}

const files = await filesUnder(dist);
if (files.some((file) => file.endsWith(".map"))) {
  throw new Error("Bundle check failed: source map artifact found.");
}
for (const file of files.filter((path) => inspectedExtensions.has(extname(path)))) {
  const content = await readFile(file, "utf8");
  for (const rule of forbidden) {
    if (rule.pattern.test(content)) {
      throw new Error(`Bundle check failed: ${rule.label} found in ${file}.`);
    }
  }
}

for (const required of ["manifest.json", "sidepanel.html", "assets/background.js", "assets/sidepanel.js"]) {
  if (!files.includes(join(dist, ...required.split("/")))) {
    throw new Error(`Bundle check failed: missing ${required}.`);
  }
}
