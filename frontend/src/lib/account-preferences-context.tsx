"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { useAuth, type User } from "@/lib/auth-context";
import type { SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";

export type AvatarTone = "emerald" | "blue" | "violet" | "amber";
export type MotionPreference = "system" | "reduced";

export interface AccountPreferences {
  displayName: string;
  avatarTone: AvatarTone;
  defaultPresentation: SecurityPresentationMode;
  motion: MotionPreference;
}

interface AccountPreferencesContextValue {
  preferences: AccountPreferences;
  updatePreferences: (changes: Partial<AccountPreferences>) => void;
  resetPreferences: () => void;
}

const STORAGE_PREFIX = "trustguard_account_preferences_v1";

function defaults(user?: User | null): AccountPreferences {
  return {
    displayName: user?.name ?? "",
    avatarTone: "emerald",
    defaultPresentation: "simple",
    motion: "system",
  };
}

function storageKey(userId: string): string {
  return `${STORAGE_PREFIX}:${encodeURIComponent(userId)}`;
}

function readPreferences(user: User): AccountPreferences {
  const fallback = defaults(user);
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(storageKey(user.id));
    if (!raw) return fallback;
    const saved = JSON.parse(raw) as Partial<AccountPreferences>;
    return {
      displayName: typeof saved.displayName === "string" && saved.displayName.trim()
        ? saved.displayName.trim().slice(0, 80)
        : fallback.displayName,
      avatarTone: ["emerald", "blue", "violet", "amber"].includes(saved.avatarTone ?? "")
        ? saved.avatarTone as AvatarTone
        : fallback.avatarTone,
      defaultPresentation: saved.defaultPresentation === "analyst" ? "analyst" : "simple",
      motion: saved.motion === "reduced" ? "reduced" : "system",
    };
  } catch {
    window.localStorage.removeItem(storageKey(user.id));
    return fallback;
  }
}

const AccountPreferencesContext = createContext<AccountPreferencesContextValue>({
  preferences: defaults(),
  updatePreferences: () => undefined,
  resetPreferences: () => undefined,
});

export function AccountPreferencesProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [preferences, setPreferences] = useState<AccountPreferences>(() => defaults(user));

  useEffect(() => {
    // Preferences are device-local in this MVP and can only be read after hydration.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setPreferences(user ? readPreferences(user) : defaults());
  }, [user]);

  useEffect(() => {
    document.documentElement.dataset.motion = preferences.motion;
    return () => {
      delete document.documentElement.dataset.motion;
    };
  }, [preferences.motion]);

  const updatePreferences = useCallback((changes: Partial<AccountPreferences>) => {
    if (!user) return;
    setPreferences((current) => {
      const updated: AccountPreferences = {
        ...current,
        ...changes,
        displayName: changes.displayName === undefined
          ? current.displayName
          : changes.displayName.trim().slice(0, 80) || user.name,
      };
      window.localStorage.setItem(storageKey(user.id), JSON.stringify(updated));
      return updated;
    });
  }, [user]);

  const resetPreferences = useCallback(() => {
    if (!user) return;
    window.localStorage.removeItem(storageKey(user.id));
    setPreferences(defaults(user));
  }, [user]);

  const value = useMemo(
    () => ({ preferences, updatePreferences, resetPreferences }),
    [preferences, resetPreferences, updatePreferences],
  );

  return <AccountPreferencesContext.Provider value={value}>{children}</AccountPreferencesContext.Provider>;
}

export function useAccountPreferences(): AccountPreferencesContextValue {
  return useContext(AccountPreferencesContext);
}

export const avatarToneClass: Record<AvatarTone, string> = {
  emerald: "border-emerald-500/25 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300",
  blue: "border-blue-500/25 bg-blue-500/12 text-blue-700 dark:text-blue-300",
  violet: "border-violet-500/25 bg-violet-500/12 text-violet-700 dark:text-violet-300",
  amber: "border-amber-500/25 bg-amber-500/12 text-amber-800 dark:text-amber-300",
};
