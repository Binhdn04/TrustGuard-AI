export interface TrustGuardApiConfig {
  baseUrl: string;
}

export type ApiEnvironment = Record<string, string | undefined>;

function clean(value: string | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

export function parseExactApiOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("TrustGuard API URL must be an absolute URL.");
  }
  const localhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(localhost && url.protocol === "http:")) {
    throw new Error("TrustGuard API URL must use HTTPS except on localhost.");
  }
  if (
    url.hostname.includes("*") ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("TrustGuard API URL must be an exact origin without wildcard, credentials, path, query or fragment.");
  }
  return url.origin;
}

export function resolveApiConfig(environment: ApiEnvironment): TrustGuardApiConfig | null {
  const value = clean(environment.VITE_TRUSTGUARD_API_URL);
  return value === null ? null : { baseUrl: parseExactApiOrigin(value) };
}

export function getBundledApiConfig(): TrustGuardApiConfig | null {
  return resolveApiConfig(import.meta.env);
}

export function buildWebSocketStreamUrl(
  config: TrustGuardApiConfig,
  analysisId: string,
  streamPath: string,
  ticket: string,
  cursor: string | null,
): string {
  const expectedPath = `/api/v4/analyses/${analysisId}/stream`;
  const url = new URL(streamPath, config.baseUrl);
  if (
    url.origin !== config.baseUrl ||
    url.pathname !== expectedPath ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  ) {
    throw new Error("WebSocket stream path does not match the configured TrustGuard API.");
  }
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("ticket", ticket);
  if (cursor !== null) url.searchParams.set("cursor", cursor);
  return url.toString();
}
