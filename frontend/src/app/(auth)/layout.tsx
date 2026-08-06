import type { ReactNode } from "react";
import { ShieldIcon } from "@/components/ui/icons";

import { ThemeToggle } from "@/components/theme-toggle";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen bg-background relative">
      {/* Absolute top-right controls */}
      <div className="absolute top-4 right-4 z-50 flex items-center gap-4">
        <div className="lg:hidden flex items-center gap-2 text-primary font-bold mr-2">
          <ShieldIcon className="w-6 h-6" />
          AI PROTECT
        </div>
        <ThemeToggle />
      </div>

      {/* Left Column - Branding (Hidden on mobile) */}
      <div className="hidden lg:flex flex-col flex-1 bg-card border-r border-border relative overflow-hidden">
        {/* Decorative background elements */}
        <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-primary/10 via-background to-background"></div>
        <div className="absolute bottom-0 right-0 w-1/2 h-1/2 bg-[radial-gradient(circle_at_bottom_right,_var(--tw-gradient-stops))] from-primary/5 via-transparent to-transparent"></div>
        
        <div className="relative z-10 flex flex-col justify-center items-center h-full p-12 text-center">
          <div className="inline-flex items-center justify-center p-4 bg-primary/10 rounded-3xl mb-8 border border-primary/20 shadow-[0_0_50px_rgba(16,185,129,0.3)]">
            <ShieldIcon className="w-16 h-16 text-primary" />
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-foreground mb-4">
            AI PROTECT
          </h1>
          <p className="text-lg text-muted-foreground max-w-md mx-auto">
            Giải pháp thông minh giúp phát hiện tin giả, lừa đảo (phishing) và các mối đe dọa trực tuyến theo thời gian thực.
          </p>
        </div>
      </div>

      {/* Right Column - Form */}
      <div className="flex-1 flex items-center justify-center p-8 sm:p-12 relative">
        
        <div className="w-full max-w-md">
          {children}
        </div>
      </div>
    </div>
  );
}
