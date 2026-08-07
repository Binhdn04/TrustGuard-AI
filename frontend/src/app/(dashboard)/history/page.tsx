"use client";

import { useState } from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle, Search, Filter } from "lucide-react";
import { cn } from "@/lib/utils";

// Mock data for History
const MOCK_HISTORY = [
  {
    id: "h1",
    content: "Việt Nam sẽ cấm hoàn toàn xe máy từ năm 2027.",
    stance: "refutes",
    claimsCount: 1,
    sourcesCount: 1,
    hasUrlWarning: false,
    date: "2024-03-15T10:30:00Z",
  },
  {
    id: "h2",
    content: "Uống nước chanh mỗi ngày có thể chữa khỏi ung thư và các bệnh khác.",
    stance: "mixed",
    claimsCount: 2,
    sourcesCount: 1,
    hasUrlWarning: false,
    date: "2024-03-14T15:20:00Z",
  },
  {
    id: "h3",
    content: "Nhận quà trúng thưởng tại https://tapdoanx-qua.example/login",
    stance: "refutes",
    claimsCount: 1,
    sourcesCount: 0,
    hasUrlWarning: true,
    date: "2024-03-14T09:15:00Z",
  },
  {
    id: "h4",
    content: "Uống đủ 2 lít nước mỗi ngày tốt cho sức khỏe.",
    stance: "supports",
    claimsCount: 1,
    sourcesCount: 1,
    hasUrlWarning: false,
    date: "2024-03-13T11:45:00Z",
  },
  {
    id: "h5",
    content: "Người ngoài hành tinh vừa đáp xuống bãi cỏ nhà tôi sáng nay.",
    stance: "unrated",
    claimsCount: 1,
    sourcesCount: 0,
    hasUrlWarning: false,
    date: "2024-03-12T08:00:00Z",
  }
];

type FilterType = "all" | "supports" | "refutes" | "mixed" | "unrated" | "url_warning";

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState<FilterType>("all");

  const filteredHistory = MOCK_HISTORY.filter(item => {
    // Text search
    if (search && !item.content.toLowerCase().includes(search.toLowerCase())) return false;
    
    // Stance/Warning filter
    if (activeFilter === "all") return true;
    if (activeFilter === "url_warning") return item.hasUrlWarning;
    return item.stance === activeFilter;
  });

  const getStanceDisplay = (stance: string) => {
    switch(stance) {
      case "supports": return { label: "Được xác nhận", icon: ShieldCheck, color: "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20" };
      case "refutes": return { label: "Bị bác bỏ", icon: ShieldAlert, color: "text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/20" };
      case "mixed": return { label: "Mixed", icon: AlertTriangle, color: "text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/20" };
      default: return { label: "Chưa rõ", icon: HelpCircle, color: "text-slate-600 dark:text-slate-400 bg-slate-500/10 border-slate-500/20" };
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-8 px-4 sm:px-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">Lịch sử kiểm chứng</h1>
        <p className="text-muted-foreground mt-2">Xem lại các nội dung bạn đã kiểm tra.</p>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input 
            type="text"
            placeholder="Tìm kiếm nội dung..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-xl border border-border bg-background text-sm outline-none focus:border-primary transition-colors"
          />
        </div>
        
        {/* Filter Dropdown (Simple native select for demo) */}
        <div className="relative w-full sm:w-48 shrink-0">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <select 
            value={activeFilter}
            onChange={(e) => setActiveFilter(e.target.value as FilterType)}
            className="w-full pl-9 pr-4 py-2 rounded-xl border border-border bg-background text-sm outline-none focus:border-primary appearance-none cursor-pointer"
          >
            <option value="all">Tất cả kết quả</option>
            <option value="supports">Được xác nhận</option>
            <option value="refutes">Bị bác bỏ</option>
            <option value="mixed">Mixed</option>
            <option value="unrated">Chưa đủ bằng chứng</option>
            <option value="url_warning">Có URL nguy hiểm</option>
          </select>
        </div>
      </div>

      {/* List */}
      <div className="space-y-4">
        {filteredHistory.length > 0 ? (
          filteredHistory.map((item) => {
            const display = getStanceDisplay(item.stance);
            const Icon = display.icon;
            
            return (
              <div key={item.id} className="p-4 sm:p-5 rounded-2xl border border-border bg-card hover:border-border/80 hover:shadow-sm transition-all cursor-pointer">
                <div className="flex flex-col sm:flex-row gap-4 justify-between items-start">
                  
                  <div className="space-y-2 flex-1 pr-4">
                    <p className="text-sm font-medium text-foreground line-clamp-2">
                      &quot;{item.content}&quot;
                    </p>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                      <span>{new Date(item.date).toLocaleDateString("vi-VN")}</span>
                      <span>•</span>
                      <span>{item.claimsCount} claim</span>
                      <span>•</span>
                      <span>{item.sourcesCount} nguồn</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap sm:flex-col items-end gap-2 shrink-0">
                    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border", display.color)}>
                      <Icon className="w-3.5 h-3.5" />
                      {display.label}
                    </span>
                    
                    {item.hasUrlWarning && (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border border-rose-500/20 bg-rose-500/10 text-rose-600 dark:text-rose-400">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        URL Nguy hiểm
                      </span>
                    )}
                  </div>
                  
                </div>
              </div>
            );
          })
        ) : (
          <div className="text-center py-12 px-4 border border-dashed rounded-2xl border-border bg-muted/10">
            <p className="text-muted-foreground">Không tìm thấy kết quả nào phù hợp.</p>
          </div>
        )}
      </div>
    </div>
  );
}
