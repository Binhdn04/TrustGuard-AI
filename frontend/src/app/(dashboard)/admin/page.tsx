"use client";

import { useAuth } from "@/lib/auth-context";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, ShieldAlert, XCircle, Search, Filter } from "lucide-react";
import { cn } from "@/lib/utils";

const mockQueue = [
  { id: "case-01", date: "05/08/2026 16:20", content: "Bạn đã trúng thưởng iPhone 15, truy cập ngay http://iphone-vn-nhanqua.com", score: 98, status: "pending", source: "System AI" },
  { id: "case-02", date: "05/08/2026 15:45", content: "Tuyển dụng nhân viên làm tại nhà, lương 500k/ngày...", score: 85, status: "pending", source: "User Report" },
  { id: "case-03", date: "05/08/2026 14:30", content: "Cập nhật ứng dụng VNeID ngay tại link sau...", score: 95, status: "pending", source: "System AI" },
];

export default function AdminReviewPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [selectedCase, setSelectedCase] = useState<typeof mockQueue[0] | null>(null);

  useEffect(() => {
    if (!isLoading && user?.role !== "security_admin") {
      router.push("/");
    }
  }, [user, isLoading, router]);

  if (!user || user.role !== "security_admin") return null;

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Admin Review Queue</h1>
          <p className="text-sm text-muted-foreground mt-1">Hàng đợi xét duyệt các case bị cảnh báo rủi ro cao</p>
        </div>
      </div>

      <div className="flex flex-1 gap-6 min-h-0">
        {/* Left: Queue Table */}
        <div className={cn("flex flex-col bg-card border border-border rounded-xl overflow-hidden transition-all duration-300", selectedCase ? "w-1/2" : "w-full")}>
          <div className="p-4 border-b border-border flex items-center gap-4 bg-muted/30">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input type="text" placeholder="Tìm kiếm theo ID, Nội dung..." className="w-full pl-9 pr-4 py-2 text-sm bg-background border border-border rounded-lg outline-none focus:ring-2 focus:ring-primary" />
            </div>
            <button className="flex items-center px-4 py-2 text-sm border border-border bg-background rounded-lg hover:bg-secondary">
              <Filter className="w-4 h-4 mr-2" />
              Lọc
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4">
            <div className="space-y-3">
              {mockQueue.map((item) => (
                <div 
                  key={item.id}
                  onClick={() => setSelectedCase(item)}
                  className={cn(
                    "p-4 rounded-xl border cursor-pointer transition-all",
                    selectedCase?.id === item.id 
                      ? "bg-primary/5 border-primary/50 shadow-[0_0_15px_rgba(16,185,129,0.1)]" 
                      : "bg-background border-border hover:border-primary/30"
                  )}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase">{item.id}</span>
                    <span className="text-xs bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 px-2 py-0.5 rounded-full flex items-center font-medium">
                      <AlertTriangle className="w-3 h-3 mr-1" /> Điểm rủi ro: {item.score}
                    </span>
                  </div>
                  <p className="text-sm font-medium text-foreground line-clamp-2">{item.content}</p>
                  <div className="mt-3 flex justify-between items-center text-xs text-muted-foreground">
                    <span>Nguồn: {item.source}</span>
                    <span>{item.date}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Detail Panel (Sliding or Inline Expansion) */}
        {selectedCase && (
          <div className="w-1/2 flex flex-col bg-card border border-border rounded-xl overflow-hidden animate-in slide-in-from-right-8 duration-300">
            <div className="p-4 border-b border-border flex justify-between items-center bg-muted/30">
              <h2 className="font-semibold text-lg flex items-center">
                <ShieldAlert className="w-5 h-5 mr-2 text-amber-500" />
                Chi tiết Case: {selectedCase.id}
              </h2>
              <button onClick={() => setSelectedCase(null)} className="p-1 rounded-md hover:bg-secondary text-muted-foreground hover:text-foreground">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div>
                <h3 className="text-sm font-semibold text-muted-foreground uppercase mb-2">Nội dung / URL gốc</h3>
                <div className="p-4 bg-muted/50 rounded-lg text-sm text-foreground break-all border border-border/50">
                  {selectedCase.content}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-muted-foreground uppercase mb-2">Phân tích từ AI</h3>
                <ul className="space-y-2 text-sm text-foreground">
                  <li className="flex items-start"><AlertTriangle className="w-4 h-4 mr-2 text-red-500 shrink-0 mt-0.5" /> Chứa liên kết chuyển hướng đáng ngờ (redirect to .su domain).</li>
                  <li className="flex items-start"><AlertTriangle className="w-4 h-4 mr-2 text-red-500 shrink-0 mt-0.5" /> Dấu hiệu lừa đảo: Thúc giục nhận quà tặng.</li>
                  <li className="flex items-start"><AlertTriangle className="w-4 h-4 mr-2 text-amber-500 shrink-0 mt-0.5" /> Tên miền mới đăng ký cách đây 2 ngày.</li>
                </ul>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-muted-foreground uppercase mb-2">WHOIS & Blacklist Info</h3>
                <div className="p-3 bg-slate-900 text-emerald-400 rounded-lg text-xs font-mono break-all whitespace-pre-wrap">
                  {`Domain Name: IPHONE-VN-NHANQUA.COM
Registry Domain ID: 263...
Registrar: NameCheap, Inc.
Creation Date: 2026-08-03T10:00:00Z
Status: clientTransferProhibited`}
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-border bg-muted/10 grid grid-cols-2 gap-3">
              <button className="flex items-center justify-center px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors">
                <CheckCircle className="w-4 h-4 mr-2" />
                Duyệt & Thêm Blacklist
              </button>
              <button className="flex items-center justify-center px-4 py-2.5 bg-secondary text-foreground hover:bg-secondary/80 rounded-lg text-sm font-medium transition-colors border border-border">
                <XCircle className="w-4 h-4 mr-2" />
                Bác bỏ cảnh báo (An toàn)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
