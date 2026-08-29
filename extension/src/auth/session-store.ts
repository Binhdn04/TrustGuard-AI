import { z } from "zod";

export const AUTH_TRANSACTION_STORAGE_KEY = "trustguard.authTransaction.v1";
export const AUTH_SESSION_STORAGE_KEY = "trustguard.authSession.v1";
export const AUTH_TRANSACTION_TTL_MS = 10 * 60 * 1_000;

export const authUserSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  email: z.string(),
  role: z.enum(["user", "security_admin"]),
}).strict();

export const authTransactionSchema = z.object({
  version: z.literal(1),
  state: z.string().min(32),
  nonce: z.string().min(32),
  codeVerifier: z.string().min(43).max(128),
  redirectUri: z.url(),
  createdAt: z.number().int().nonnegative(),
}).strict();

export const authSessionSchema = z.object({
  version: z.literal(1),
  accessToken: z.string().min(1),
  idToken: z.string().min(1),
  refreshToken: z.string().min(1).nullable(),
  expiresAt: z.number().int().positive(),
  user: authUserSchema,
}).strict();

export type AuthTransaction = z.infer<typeof authTransactionSchema>;
export type AuthSession = z.infer<typeof authSessionSchema>;

export interface AuthSessionStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

export class AuthSessionStore {
  constructor(private readonly storage: AuthSessionStorageArea) {}

  async saveTransaction(transaction: AuthTransaction): Promise<void> {
    await this.storage.set({ [AUTH_TRANSACTION_STORAGE_KEY]: authTransactionSchema.parse(transaction) });
  }

  async readTransaction(): Promise<AuthTransaction | null> {
    const value = (await this.storage.get(AUTH_TRANSACTION_STORAGE_KEY))[AUTH_TRANSACTION_STORAGE_KEY];
    const parsed = authTransactionSchema.safeParse(value);
    if (!parsed.success && value !== undefined) await this.storage.remove(AUTH_TRANSACTION_STORAGE_KEY);
    return parsed.success ? parsed.data : null;
  }

  async clearTransaction(): Promise<void> {
    await this.storage.remove(AUTH_TRANSACTION_STORAGE_KEY);
  }

  async saveSession(session: AuthSession): Promise<void> {
    await this.storage.set({ [AUTH_SESSION_STORAGE_KEY]: authSessionSchema.parse(session) });
  }

  async readSession(): Promise<AuthSession | null> {
    const value = (await this.storage.get(AUTH_SESSION_STORAGE_KEY))[AUTH_SESSION_STORAGE_KEY];
    const parsed = authSessionSchema.safeParse(value);
    if (!parsed.success && value !== undefined) await this.storage.remove(AUTH_SESSION_STORAGE_KEY);
    return parsed.success ? parsed.data : null;
  }

  async clearAll(): Promise<void> {
    await this.storage.remove([AUTH_TRANSACTION_STORAGE_KEY, AUTH_SESSION_STORAGE_KEY]);
  }
}
