import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { AccountPreferencesProvider } from "@/lib/account-preferences-context";
import { AuthProvider } from "@/lib/auth-context";

export const metadata: Metadata = {
  title: "AI PROTECT — Kiểm tra tin nhắn và URL",
  description:
    "AI Agent phát hiện và cảnh báo tin giả, phishing và liên kết độc hại có giải thích.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="vi"
      className="h-full antialiased"
      suppressHydrationWarning
    >
      <body className="min-h-full flex flex-col">
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
          <AuthProvider>
            <AccountPreferencesProvider>{children}</AccountPreferencesProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
