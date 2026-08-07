"use client";

import { useState, type FormEvent } from "react";
import { Link as LinkIcon, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

interface UrlScannerComposerProps {
  onSubmit: (url: string) => void;
  isLoading?: boolean;
}

export function UrlScannerComposer({ onSubmit, isLoading = false }: UrlScannerComposerProps) {
  const [url, setUrl] = useState("");
  const [isFocused, setIsFocused] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateUrl = (text: string) => {
    if (!text.trim()) return false;
    try {
      new URL(text);
      return true;
    } catch {
      return false;
    }
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    
    if (!validateUrl(trimmed)) {
      setError("Vui lòng nhập một địa chỉ URL hợp lệ (bắt đầu bằng http:// hoặc https://)");
      return;
    }
    
    setError(null);
    onSubmit(trimmed);
  };

  return (
    <div className="w-full max-w-3xl mx-auto">
      <div className="text-center space-y-3 mb-8">
        <h2 className="text-3xl font-bold tracking-tight text-foreground">
          Quét Link Độc hại
        </h2>
        <p className="text-muted-foreground">
          Dán một đường dẫn (URL) đáng ngờ để kiểm tra mã độc, lừa đảo hoặc website giả mạo.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div 
          className={cn(
            "relative rounded-2xl transition-all duration-300 p-1 bg-gradient-to-r",
            isFocused 
              ? "from-blue-500/40 to-purple-500/40 shadow-xl shadow-blue-500/10" 
              : "from-border to-border hover:from-blue-500/20 hover:to-purple-500/20"
          )}
        >
          <div className="relative rounded-xl bg-card overflow-hidden flex flex-col md:flex-row items-center gap-2 p-2">
            <div className="flex-1 flex items-center w-full bg-transparent px-3">
              <LinkIcon className="w-5 h-5 text-muted-foreground shrink-0 mr-3" />
              <input
                type="url"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  if (error) setError(null);
                }}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                placeholder="https://example.com/scam-link"
                className="w-full py-3 bg-transparent outline-none text-[15px] text-foreground placeholder:text-muted-foreground disabled:opacity-50"
                disabled={isLoading}
              />
            </div>
            
            <button
              type="submit"
              disabled={!url.trim() || isLoading}
              className="w-full md:w-auto shrink-0 flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-blue-600 text-white font-semibold hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all active:scale-95 shadow-sm"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <ShieldCheck className="w-4 h-4" />
              )}
              {isLoading ? "Đang quét..." : "Quét Link"}
            </button>
          </div>
        </div>
        
        {error && (
          <p className="text-sm text-rose-500 text-center font-medium animate-in fade-in">
            {error}
          </p>
        )}
      </form>
    </div>
  );
}
