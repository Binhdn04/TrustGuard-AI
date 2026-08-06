"use client";

import React, { createContext, useContext, useState, useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";

export type Role = "user" | "security_admin";

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      // Check local storage for the demo session after hydration.
      const storedUser = localStorage.getItem("ai_protect_user");
      if (storedUser) {
        try {
          setUser(JSON.parse(storedUser));
        } catch {
          localStorage.removeItem("ai_protect_user");
        }
      }
      setIsLoading(false);
    }, 0);
    return () => window.clearTimeout(timeout);
  }, []);

  useEffect(() => {
    // Redirect logic
    if (!isLoading) {
      const isAuthPage = pathname.startsWith("/login") || pathname.startsWith("/register");
      if (!user && !isAuthPage) {
        router.push("/login");
      } else if (user && isAuthPage) {
        router.push("/");
      }
    }
  }, [user, isLoading, pathname, router]);

  const login = (newUser: User) => {
    setUser(newUser);
    localStorage.setItem("ai_protect_user", JSON.stringify(newUser));
    router.push("/");
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("ai_protect_user");
    router.push("/login");
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
