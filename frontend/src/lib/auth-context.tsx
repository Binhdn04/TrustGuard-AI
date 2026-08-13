"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import {
  clearOidcSession,
  getOidcLogoutUrl,
  loadOidcSession,
  oidcRefreshDelay,
  refreshOidcSession,
  restoreOidcSession,
  saveOidcSession,
  type OidcSession,
  type User,
} from "@/lib/auth/oidc";

export type { Role, User } from "@/lib/auth/oidc";

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (user: User) => void;
  establishOidcSession: (session: OidcSession) => void;
  logout: () => void;
}

const DEMO_USER_KEY = "ai_protect_user";
const AuthContext = createContext<AuthContextType | undefined>(undefined);

function loadDemoUser(): User | null {
  try {
    const value = window.localStorage.getItem(DEMO_USER_KEY);
    if (!value) return null;
    const user = JSON.parse(value) as Partial<User>;
    if (
      typeof user.id !== "string"
      || typeof user.name !== "string"
      || typeof user.email !== "string"
      || (user.role !== "user" && user.role !== "security_admin")
    ) {
      throw new Error("Invalid demo session");
    }
    return user as User;
  } catch {
    window.localStorage.removeItem(DEMO_USER_KEY);
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [oidcSession, setOidcSession] = useState<OidcSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    let cancelled = false;
    void restoreOidcSession().then((session) => {
      if (cancelled) return;
      if (session) {
        setOidcSession(session);
        setUser(session.user);
      } else {
        setUser(loadDemoUser());
      }
      setIsLoading(false);
    });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!oidcSession) return;
    const timer = window.setTimeout(() => {
      if (!oidcSession.refreshToken) {
        clearOidcSession();
        setOidcSession(null);
        setUser(null);
        router.replace("/login?reason=session_expired");
        return;
      }
      void refreshOidcSession(oidcSession)
        .then((session) => {
          setOidcSession(session);
          setUser(session.user);
        })
        .catch(() => {
          clearOidcSession();
          setOidcSession(null);
          setUser(null);
          router.replace("/login?reason=session_expired");
        });
    }, oidcRefreshDelay(oidcSession));
    return () => window.clearTimeout(timer);
  }, [oidcSession, router]);

  useEffect(() => {
    if (isLoading) return;
    const isCallback = pathname.startsWith("/auth/callback");
    const isLoginOrRegister = pathname.startsWith("/login") || pathname.startsWith("/register");
    if (!user && !isCallback && !isLoginOrRegister) {
      router.replace(`/login?returnTo=${encodeURIComponent(pathname)}`);
    } else if (user && isLoginOrRegister) {
      router.replace("/");
    }
  }, [user, isLoading, pathname, router]);

  const login = useCallback((newUser: User) => {
    clearOidcSession();
    setOidcSession(null);
    setUser(newUser);
    window.localStorage.setItem(DEMO_USER_KEY, JSON.stringify(newUser));
    router.replace("/");
  }, [router]);

  const establishOidcSession = useCallback((session: OidcSession) => {
    saveOidcSession(session);
    setOidcSession(session);
    setUser(session.user);
  }, []);

  const logout = useCallback(() => {
    const logoutUrl = oidcSession ? getOidcLogoutUrl() : null;
    clearOidcSession();
    window.localStorage.removeItem(DEMO_USER_KEY);
    setOidcSession(null);
    setUser(null);
    if (logoutUrl) {
      window.location.assign(logoutUrl);
    } else {
      router.replace("/login");
    }
  }, [oidcSession, router]);

  return (
    <AuthContext.Provider value={{ user, isLoading, login, establishOidcSession, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) throw new Error("useAuth must be used within an AuthProvider");
  return context;
}

export function currentOidcSession(): OidcSession | null {
  if (typeof window === "undefined") return null;
  return loadOidcSession();
}
