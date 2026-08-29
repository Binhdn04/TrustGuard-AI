import { execFileSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, resolve } from "node:path";

const root = resolve(".");
const sourceRoot = resolve("src");
const distRoot = resolve("dist");
const textExtensions = new Set([".css", ".html", ".js", ".json", ".ts"]);

const sourceRules = [
  { label: "runtime console logging", pattern: /\bconsole\s*\./u },
  { label: "document.write DOM sink", pattern: /\bdocument\s*\.\s*write\s*\(/u },
  { label: "innerHTML DOM sink", pattern: /\.\s*innerHTML\s*=/u },
  { label: "insertAdjacentHTML DOM sink", pattern: /\.\s*insertAdjacentHTML\s*\(/u },
  { label: "dynamic eval", pattern: /\beval\s*\(/u },
  { label: "dynamic Function constructor", pattern: /\bnew\s+Function\s*\(/u },
  { label: "external message listener", pattern: /\bon(?:Message|Connect)External\b/u },
  { label: "persistent extension storage", pattern: /\bchrome\s*\.\s*storage\s*\.\s*(?:local|sync)\b/u },
  { label: "page Web Storage", pattern: /\b(?:localStorage|sessionStorage)\b/u },
  { label: "remote dynamic import", pattern: /\bimport\s*\(\s*["'`]https?:\/\//iu },
  { label: "remote worker import", pattern: /\bimportScripts\s*\(\s*["'`]https?:\/\//iu },
];

const artifactSecretRules = [
  { label: "private key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/u },
  { label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/u },
  { label: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/u },
  { label: "compact JWT", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u },
  { label: "literal bearer credential", pattern: /\bBearer\s+[A-Za-z0-9._~-]{12,}\b/iu },
  { label: "credential-bearing URL", pattern: /https?:\/\/[^\s/"'`]+:[^\s/@"'`]+@/iu },
];

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(path)));
    else if (textExtensions.has(extname(path))) files.push(path);
  }
  return files;
}

async function scan(directory, rules) {
  for (const file of await filesUnder(directory)) {
    const content = await readFile(file, "utf8");
    for (const rule of rules) {
      if (rule.pattern.test(content)) {
        throw new Error(`Security check failed: ${rule.label} found in ${relative(root, file)}.`);
      }
    }
  }
}

function assertIgnored(path) {
  try {
    execFileSync("git", ["check-ignore", "--quiet", path], {
      cwd: root,
      stdio: "ignore",
    });
  } catch {
    throw new Error(`Security check failed: ${path} must remain ignored by Git.`);
  }
}

await scan(sourceRoot, sourceRules);
await scan(distRoot, artifactSecretRules);
assertIgnored(".env.local");

const background = await readFile(join(distRoot, "assets", "background.js"), "utf8");
if (!background.includes("TRUSTED_CONTEXTS")) {
  throw new Error("Security check failed: session storage must remain restricted to trusted extension contexts.");
}

console.log("Security check passed: source sinks, storage boundary, ignored local config and artifact secrets.");
