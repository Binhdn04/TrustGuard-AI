"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { ShieldCheck, ArrowRight, Loader2 } from "lucide-react";

interface SmartInputProps {
  onSubmit: (content: string, hasConsent: boolean) => void;
  isLoading?: boolean;
}

export function SmartInput({ onSubmit, isLoading }: SmartInputProps) {
  const [content, setContent] = React.useState("");
  const [hasConsent, setHasConsent] = React.useState(false);
  const [isFocused, setIsFocused] = React.useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    onSubmit(content, hasConsent);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-3xl mx-auto space-y-4">
      <div 
        className={cn(
          "relative rounded-xl transition-all duration-300 p-1",
          isFocused ? "bg-gradient-to-r from-primary to-emerald-400 shadow-lg shadow-primary/20" : "bg-border/50"
        )}
      >
        <div className="relative rounded-lg bg-background/95 backdrop-blur-md overflow-hidden">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            placeholder="Dán URL, tin nhắn hoặc thông báo đáng ngờ vào đây để phân tích..."
            className="w-full min-h-[120px] p-4 bg-transparent resize-none outline-none text-foreground placeholder:text-muted-foreground"
            disabled={isLoading}
          />
          <div className="absolute bottom-3 right-3">
            <button
              type="submit"
              disabled={!content.trim() || isLoading}
              className="flex items-center justify-center w-10 h-10 rounded-full bg-primary text-primary-foreground hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ArrowRight className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>
      
      <div className="flex items-center space-x-2 text-sm text-muted-foreground">
        <label className="flex items-center cursor-pointer group">
          <div className="relative flex items-center justify-center w-5 h-5 mr-2 border rounded border-input bg-background group-hover:border-primary transition-colors">
            <input
              type="checkbox"
              className="peer sr-only"
              checked={hasConsent}
              onChange={(e) => setHasConsent(e.target.checked)}
              disabled={isLoading}
            />
            <div className={cn(
              "absolute inset-0 bg-primary rounded opacity-0 peer-checked:opacity-100 transition-opacity flex items-center justify-center"
            )}>
              <ShieldCheck className="w-3.5 h-3.5 text-primary-foreground" />
            </div>
          </div>
          <span>Đồng ý cho hệ thống kiểm tra URL trên công cụ bên ngoài (VirusTotal, v.v.)</span>
        </label>
      </div>
    </form>
  );
}
