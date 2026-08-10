"use client";

import { useState, type FormEvent, useMemo } from "react";
import { ShieldCheck, Search, Link as LinkIcon, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

const EXAMPLES = [
  "Việt Nam sẽ cấm hoàn toàn xe máy từ năm 2027.",
  "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư.",
  "Nhận quà trúng thưởng tại https://tapdoanx-qua.example/login",
];

interface FactCheckComposerProps {
  onSubmit: (content: string, consentToScanUrls: boolean) => void;
  isLoading?: boolean;
}

export function FactCheckComposer({ onSubmit, isLoading = false }: FactCheckComposerProps) {
  const [content, setContent] = useState("");
  const [consent, setConsent] = useState(false);
  const [isFocused, setIsFocused] = useState(false);

  // Auto detect URLs in the content
  const detectedUrls = useMemo(() => {
    const urlPattern = /https?:\/\/[^\s]+/giu;
    return content.match(urlPattern) || [];
  }, [content]);

  const hasUrls = detectedUrls.length > 0;

  const updateContent = (nextContent: string) => {
    setContent(nextContent);
    if (!/https?:\/\/[^\s]+/iu.test(nextContent)) setConsent(false);
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    onSubmit(content.trim(), hasUrls && consent);
  };

  return (
    <div className="w-full max-w-3xl mx-auto">
      <div className="text-center space-y-3 mb-8">
        <h2 className="text-3xl font-bold tracking-tight text-foreground">
          Kiểm chứng một thông tin
        </h2>
        <p className="text-muted-foreground">
          Dán phát biểu, bài viết, tin nhắn hoặc nội dung mạng xã hội bạn muốn kiểm chứng.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div 
          className={cn(
            "relative rounded-2xl transition-all duration-300 p-1 bg-gradient-to-r",
            isFocused 
              ? "from-primary/40 to-blue-500/40 shadow-xl shadow-primary/10" 
              : "from-border to-border hover:from-primary/20 hover:to-blue-500/20"
          )}
        >
          <div className="relative rounded-xl bg-card overflow-hidden flex flex-col">
            <textarea
              value={content}
              onChange={(e) => updateContent(e.target.value)}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setIsFocused(false)}
              placeholder="Ví dụ: “Uống nước chanh có thể chữa khỏi ung thư…”"
              className="w-full min-h-[160px] p-5 bg-transparent resize-y outline-none text-[15px] leading-relaxed text-foreground placeholder:text-muted-foreground disabled:opacity-50"
              disabled={isLoading}
              maxLength={5000}
            />
            
            <div className="px-5 py-3 bg-muted/30 border-t border-border flex items-center justify-between">
              <span className="text-xs font-medium tabular-nums text-muted-foreground">
                {content.length.toLocaleString("vi-VN")} / 5.000
              </span>
              <button
                type="submit"
                disabled={!content.trim() || isLoading}
                className="flex items-center gap-2 px-5 py-2.5 rounded-full bg-primary text-primary-foreground font-semibold hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all active:scale-95 shadow-sm"
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                {isLoading ? "Đang phân tích..." : "Phân tích"}
              </button>
            </div>
          </div>
        </div>

        {/* Mẫu thử nghiệm */}
        <div className="flex flex-wrap items-center gap-2 justify-center mt-4">
          <span className="text-xs text-muted-foreground font-medium mr-1">Nội dung mẫu:</span>
          {EXAMPLES.map((example, index) => (
            <button
              key={index}
              type="button"
              disabled={isLoading}
              onClick={() => updateContent(example)}
              className="px-3 py-1.5 rounded-full bg-secondary/50 border border-border text-xs font-medium text-secondary-foreground hover:bg-secondary hover:border-primary/30 transition-colors disabled:opacity-50"
            >
              Mẫu {index + 1}
            </button>
          ))}
        </div>

        {/* Detected URL Panel */}
        {hasUrls && (
          <div className="mt-6 p-4 rounded-xl border border-border bg-card shadow-sm animate-in fade-in slide-in-from-top-4 duration-300">
            <div className="flex items-start gap-3">
              <div className="mt-1 flex-shrink-0 p-1.5 bg-blue-500/10 rounded-lg text-blue-600 dark:text-blue-400">
                <LinkIcon className="w-4 h-4" />
              </div>
              <div className="flex-1 space-y-3">
                <div>
                  <h4 className="text-sm font-semibold text-foreground">Phát hiện liên kết đính kèm</h4>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Đã tìm thấy {detectedUrls.length} URL trong nội dung của bạn.
                  </p>
                </div>
                
                <div className="flex flex-wrap gap-2">
                  {detectedUrls.map((url, i) => (
                    <span key={i} className="inline-flex items-center px-2.5 py-1 rounded-md bg-secondary text-xs text-secondary-foreground truncate max-w-[200px]">
                      {url}
                    </span>
                  ))}
                </div>

                <label className="flex items-start gap-3 mt-4 cursor-pointer group p-3 rounded-lg border border-border bg-background hover:border-primary/50 transition-colors has-[:checked]:border-primary/50 has-[:checked]:bg-primary/5">
                  <div className="relative flex items-center justify-center w-5 h-5 mt-0.5 border rounded border-input bg-background group-hover:border-primary transition-colors">
                    <input
                      type="checkbox"
                      className="peer absolute inset-0 z-10 size-full cursor-pointer opacity-0"
                      checked={consent}
                      onChange={(e) => setConsent(e.target.checked)}
                      disabled={isLoading}
                    />
                    <div className={cn(
                      "pointer-events-none absolute inset-0 bg-primary rounded opacity-0 peer-checked:opacity-100 transition-opacity flex items-center justify-center"
                    )}>
                      <ShieldCheck className="w-3.5 h-3.5 text-primary-foreground" />
                    </div>
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-foreground block">
                      Kiểm tra thêm độ an toàn của các liên kết
                    </span>
                    <span className="text-xs text-muted-foreground block mt-1">
                      URL và metadata cần thiết có thể được gửi đến dịch vụ bảo mật bên ngoài. Việc này không ảnh hưởng đến quá trình kiểm chứng nội dung.
                    </span>
                  </div>
                </label>
              </div>
            </div>
          </div>
        )}
      </form>
    </div>
  );
}
