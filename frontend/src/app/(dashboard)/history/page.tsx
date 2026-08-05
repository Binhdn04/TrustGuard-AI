"use client";

import { Clock, ShieldAlert, ShieldCheck } from "lucide-react";

const mockHistory = [
  { id: 1, date: "05/08/2026 15:30", content: "Chúc mừng bạn đã trúng thưởng iPhone 15 Pro Max...", score: 92, status: "malicious" },
  { id: 2, date: "05/08/2026 14:15", content: "Đây là link tài liệu cuộc họp sáng nay nhé: docs.google.com/...", score: 15, status: "safe" },
  { id: 3, date: "04/08/2026 09:00", content: "Vui lòng đăng nhập lại tài khoản ngân hàng VCB tại link sau...", score: 98, status: "malicious" },
  { id: 4, date: "03/08/2026 16:45", content: "Bạn có rảnh không, mượn tạm 5 triệu chuyển vào tài khoản này nhé...", score: 75, status: "suspicious" },
];

export default function HistoryPage() {
  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Lịch sử phân tích</h1>
          <p className="text-sm text-muted-foreground mt-1">Danh sách các nội dung bạn đã yêu cầu hệ thống kiểm tra</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-muted-foreground uppercase bg-muted/50 border-b border-border">
              <tr>
                <th className="px-6 py-4 font-semibold">Thời gian</th>
                <th className="px-6 py-4 font-semibold w-1/2">Nội dung / URL</th>
                <th className="px-6 py-4 font-semibold text-center">Điểm rủi ro</th>
                <th className="px-6 py-4 font-semibold">Trạng thái</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {mockHistory.map((item) => (
                <tr key={item.id} className="hover:bg-muted/50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap text-muted-foreground flex items-center">
                    <Clock className="w-4 h-4 mr-2" />
                    {item.date}
                  </td>
                  <td className="px-6 py-4 font-medium text-foreground truncate max-w-[300px]">
                    {item.content}
                  </td>
                  <td className="px-6 py-4 text-center">
                    <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-secondary font-bold">
                      {item.score}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {item.status === "malicious" && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 border border-red-200 dark:border-red-800/50">
                        <ShieldAlert className="w-3 h-3 mr-1" /> Độc hại
                      </span>
                    )}
                    {item.status === "suspicious" && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50">
                        <ShieldAlert className="w-3 h-3 mr-1" /> Đáng ngờ
                      </span>
                    )}
                    {item.status === "safe" && (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
                        <ShieldCheck className="w-3 h-3 mr-1" /> An toàn
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
