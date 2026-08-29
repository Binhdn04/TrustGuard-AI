import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadEnv } from "vite";

import { resolveOidcBuildPolicy } from "./oidc-build-config.mjs";

const manifestPath = resolve("dist/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const expectedPermissions = ["sidePanel", "contextMenus", "storage", "identity"];
const environment = { ...loadEnv("production", process.cwd(), "VITE_"), ...process.env };
const oidcPolicy = resolveOidcBuildPolicy(environment);
const forbiddenLocalKeys = [
  "content_scripts",
  "externally_connectable",
  "key",
  "oauth2",
  "optional_host_permissions",
  "optional_permissions",
  "web_accessible_resources",
];

function fail(message) {
  throw new Error(`Manifest check failed: ${message}`);
}

if (manifest.manifest_version !== 3) fail("Manifest V3 is required.");
if (manifest.minimum_chrome_version !== "116") fail("Chrome 116+ baseline is required.");
if (JSON.stringify(manifest.permissions) !== JSON.stringify(expectedPermissions)) {
  fail(`permissions must be exactly ${JSON.stringify(expectedPermissions)}.`);
}
for (const key of forbiddenLocalKeys) {
  if (key in manifest) fail(`local scaffold cannot declare ${key}.`);
}
if (JSON.stringify(manifest.host_permissions) !== JSON.stringify(oidcPolicy.hostPermissions)) {
  fail(`host_permissions must be exactly ${JSON.stringify(oidcPolicy.hostPermissions)}.`);
}
if (manifest.background?.service_worker !== "assets/background.js") fail("background worker path drifted.");
if (manifest.side_panel?.default_path !== "sidepanel.html") fail("Side Panel entry is missing.");

const csp = manifest.content_security_policy?.extension_pages;
const expectedCsp = `script-src 'self'; object-src 'self'; connect-src ${oidcPolicy.connectSource}; img-src 'self'; style-src 'self'`;
if (csp !== expectedCsp) fail("extension CSP must keep the local-only network and executable-code boundary.");
