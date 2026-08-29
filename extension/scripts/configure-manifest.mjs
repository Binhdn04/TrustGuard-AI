import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadEnv } from "vite";

import { resolveOidcBuildPolicy } from "./oidc-build-config.mjs";

const manifestPath = resolve("dist/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const environment = { ...loadEnv("production", process.cwd(), "VITE_"), ...process.env };
const policy = resolveOidcBuildPolicy(environment);

if (policy.hostPermissions === undefined) delete manifest.host_permissions;
else manifest.host_permissions = policy.hostPermissions;
manifest.content_security_policy.extension_pages =
  `script-src 'self'; object-src 'self'; connect-src ${policy.connectSource}; img-src 'self'; style-src 'self'`;

await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
