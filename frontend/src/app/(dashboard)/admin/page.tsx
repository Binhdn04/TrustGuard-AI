"use client";

import { useState } from "react";
import { CheckCircle2, XCircle, AlertTriangle, ShieldCheck, ShieldAlert, FileText, Link as LinkIcon, MoreVertical } from "lucide-react";
import { cn } from "@/lib/utils";

// --- Mock Data ---
const MOCK_REVIEWS = [
  {
    id: "rev1",
    originalContent: "Thuốc X chữa khỏi ung thư dạ dày 100%.",
    extractedClaim: "Thuốc X chữa khỏi ung thư dạ dày.",
    aiStance: "refutes",
    evidenceCount: 0,
    limitations: ["Cần chuyên gia y tế xác nhận."],
    status: "pending",
  }
];

const MOCK_URLS = [
  {
    id: "url1",
    domain: "tapdoanx-qua.example",
    verdict: "suspicious",
    blacklistStatus: "not_listed",
    intelligence: "Domain mới đăng ký 2 ngày, chứa từ khóa mạo danh.",
    redirects: 2,
    status: "pending",
  }
];

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<"factcheck" | "url">("factcheck");
  const [reviews, setReviews] = useState(MOCK_REVIEWS);
  const [urls, setUrls] = useState(MOCK_URLS);
  
  // Dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    action: () => void;
  }>({ isOpen: false, title: "", message: "", action: () => {} });

  const handleAction = (title: string, message: string, action: () => void) => {
    setConfirmDialog({ isOpen: true, title, message, action });
  };

  const closeDialog = () => setConfirmDialog(prev => ({ ...prev, isOpen: false }));

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6">
      
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">Admin Workspace</h1>
        <p className="text-muted-foreground mt-2">Khu vực kiểm duyệt dành cho Human-in-the-loop và Security Admin.</p>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 p-1 bg-muted rounded-xl mb-6 max-w-sm">
        <button
          onClick={() => setActiveTab("factcheck")}
          className={cn("flex-1 py-2 px-3 text-sm font-medium rounded-lg transition-colors", activeTab === "factcheck" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
        >
          Fact-check Review
        </button>
        <button
          onClick={() => setActiveTab("url")}
          className={cn("flex-1 py-2 px-3 text-sm font-medium rounded-lg transition-colors", activeTab === "url" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
        >
          URL Security
        </button>
      </div>

      {/* Content */}
      <div className="space-y-6">
        
        {/* --- Tab: Fact-Check --- */}
        {activeTab === "factcheck" && (
          <div className="space-y-4">
            {reviews.map(review => (
              <div key={review.id} className={cn("p-5 rounded-2xl border bg-card", review.status !== "pending" && "opacity-60")}>
                <div className="flex flex-col md:flex-row gap-6">
                  
                  {/* Info */}
                  <div className="flex-1 space-y-4">
                    <div>
                      <h4 className="text-xs font-semibold uppercase text-muted-foreground mb-1">Nội dung gốc</h4>
                      <p className="text-sm font-medium">"{review.originalContent}"</p>
                    </div>
                    
                    <div className="p-3 bg-muted/50 rounded-xl border border-border">
                      <h4 className="text-xs font-semibold uppercase text-muted-foreground mb-1 flex items-center gap-1.5"><FileText className="w-3.5 h-3.5" /> Claim được trích xuất</h4>
                      <p className="text-sm font-medium">"{review.extractedClaim}"</p>
                      
                      <div className="mt-3 flex items-center gap-4">
                        <div>
                          <span className="text-[10px] text-muted-foreground block mb-0.5">Kết luận AI:</span>
                          <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase", review.aiStance === "refutes" ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20" : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20")}>
                            {review.aiStance}
                          </span>
                        </div>
                        <div>
                          <span className="text-[10px] text-muted-foreground block mb-0.5">Evidence:</span>
                          <span className="text-xs font-medium">{review.evidenceCount} nguồn</span>
                        </div>
                      </div>
                    </div>
                    
                    {review.limitations.length > 0 && (
                      <div className="text-xs text-amber-600 dark:text-amber-400 flex gap-1.5 bg-amber-500/10 p-2 rounded-lg border border-amber-500/20">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>Limitation: {review.limitations.join(" ")}</span>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  {review.status === "pending" ? (
                    <div className="flex flex-row md:flex-col gap-2 shrink-0">
                      <button 
                        onClick={() => handleAction("Approve AI Result", "Xác nhận kết luận của AI là chính xác?", () => setReviews(r => r.map(x => x.id === review.id ? {...x, status: "approved"} : x)))}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 rounded-xl text-sm font-semibold transition-colors"
                      >
                        <CheckCircle2 className="w-4 h-4" /> Approve
                      </button>
                      <button 
                        onClick={() => handleAction("Reject AI Result", "Bác bỏ kết luận của AI và chỉnh sửa thủ công?", () => setReviews(r => r.map(x => x.id === review.id ? {...x, status: "rejected"} : x)))}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 rounded-xl text-sm font-semibold transition-colors"
                      >
                        <XCircle className="w-4 h-4" /> Reject
                      </button>
                      <button 
                        onClick={() => handleAction("Escalate", "Chuyển case này cho senior reviewer?", () => setReviews(r => r.map(x => x.id === review.id ? {...x, status: "escalated"} : x)))}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-background border border-border hover:bg-muted text-foreground rounded-xl text-sm font-semibold transition-colors"
                      >
                        <MoreVertical className="w-4 h-4" /> Escalate
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center shrink-0 w-32 border border-dashed rounded-xl border-border bg-muted/30">
                      <span className="text-sm font-medium text-muted-foreground capitalize">{review.status}</span>
                    </div>
                  )}

                </div>
              </div>
            ))}
          </div>
        )}

        {/* --- Tab: URL Security --- */}
        {activeTab === "url" && (
          <div className="space-y-4">
            {urls.map(url => (
              <div key={url.id} className={cn("p-5 rounded-2xl border bg-card", url.status !== "pending" && "opacity-60")}>
                <div className="flex flex-col md:flex-row gap-6">
                  
                  {/* Info */}
                  <div className="flex-1 space-y-3">
                    <div className="flex items-center gap-2">
                      <LinkIcon className="w-4 h-4 text-muted-foreground" />
                      <h4 className="text-sm font-bold truncate">{url.domain}</h4>
                      <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold uppercase", url.verdict === "suspicious" ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20" : "bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20")}>
                        {url.verdict}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <span className="text-[10px] text-muted-foreground block mb-0.5">Blacklist Status:</span>
                        <span className="text-xs font-semibold">{url.blacklistStatus}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-muted-foreground block mb-0.5">Redirects:</span>
                        <span className="text-xs font-semibold">{url.redirects} hops</span>
                      </div>
                    </div>

                    <div className="p-3 bg-muted/50 rounded-xl border border-border text-sm">
                      <span className="text-xs font-semibold text-muted-foreground block mb-1">Domain Intelligence:</span>
                      {url.intelligence}
                    </div>
                  </div>

                  {/* Actions */}
                  {url.status === "pending" ? (
                    <div className="flex flex-row md:flex-col gap-2 shrink-0">
                      <button 
                        onClick={() => handleAction("Thêm vào Blacklist", `Xác nhận thêm domain ${url.domain} vào danh sách đen?`, () => setUrls(u => u.map(x => x.id === url.id ? {...x, status: "blacklisted"} : x)))}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 rounded-xl text-sm font-semibold transition-colors"
                      >
                        <ShieldAlert className="w-4 h-4" /> Blacklist
                      </button>
                      <button 
                        onClick={() => handleAction("Đánh dấu An toàn", `Bỏ qua cảnh báo cho domain ${url.domain}?`, () => setUrls(u => u.map(x => x.id === url.id ? {...x, status: "ignored"} : x)))}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 rounded-xl text-sm font-semibold transition-colors"
                      >
                        <ShieldCheck className="w-4 h-4" /> Safe
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center shrink-0 w-32 border border-dashed rounded-xl border-border bg-muted/30">
                      <span className="text-sm font-medium text-muted-foreground capitalize">{url.status}</span>
                    </div>
                  )}

                </div>
              </div>
            ))}
          </div>
        )}

      </div>

      {/* Confirmation Dialog Overlay */}
      {confirmDialog.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="bg-card w-full max-w-sm rounded-2xl border shadow-xl p-6 animate-in zoom-in-95 duration-200">
            <h3 className="text-lg font-bold mb-2">{confirmDialog.title}</h3>
            <p className="text-sm text-muted-foreground mb-6">{confirmDialog.message}</p>
            <div className="flex gap-3 justify-end">
              <button 
                onClick={closeDialog}
                className="px-4 py-2 rounded-xl text-sm font-medium hover:bg-muted transition-colors"
              >
                Hủy
              </button>
              <button 
                onClick={() => { confirmDialog.action(); closeDialog(); }}
                className="px-4 py-2 rounded-xl text-sm font-medium bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
              >
                Xác nhận
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
