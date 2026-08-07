"use client";

import { useState } from "react";
import { SmartInput } from "./smart-input";
import { ProgressStepper, AnalysisStep } from "./progress-stepper";
import { VerdictCard, RiskLevel } from "./verdict-card";
import { Shield } from "lucide-react";

export function AnalysisWorkspace() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showResult, setShowResult] = useState(false);
  
  const [steps, setSteps] = useState<AnalysisStep[]>([
    { id: "extract", label: "Phân tách dữ liệu", status: "pending", description: "Trích xuất URL và các tuyên bố từ tin nhắn" },
    { id: "scan", label: "Quét URL & Domain", status: "pending", description: "Kiểm tra danh sách đen và VirusTotal" },
    { id: "fact-check", label: "Xác minh thông tin", status: "pending", description: "Đối chiếu với cơ sở dữ liệu tin giả" },
    { id: "score", label: "Đánh giá rủi ro", status: "pending", description: "Tính điểm dựa trên bằng chứng thu thập được" },
  ]);

  const [verdict, setVerdict] = useState<{
    score: number;
    level: RiskLevel;
    reason: string;
    recommendation: string;
    limitations?: string[];
  } | null>(null);

  const simulateAnalysis = (content: string, hasConsent: boolean) => {
    setIsAnalyzing(true);
    setShowResult(false);
    
    // Reset steps
    setSteps(steps.map(s => ({ ...s, status: "pending" })));

    // Step 1: Extract
    setTimeout(() => {
      setSteps(prev => prev.map(s => s.id === "extract" ? { ...s, status: "running" } : s));
    }, 500);

    // Step 2: Scan
    setTimeout(() => {
      setSteps(prev => prev.map(s => {
        if (s.id === "extract") return { ...s, status: "completed" };
        if (s.id === "scan") return { ...s, status: "running" };
        return s;
      }));
    }, 1500);

    // Step 3: Fact-check
    setTimeout(() => {
      setSteps(prev => prev.map(s => {
        if (s.id === "scan") return { ...s, status: "completed" };
        if (s.id === "fact-check") return { ...s, status: "running" };
        return s;
      }));
    }, 3000);

    // Step 4: Score
    setTimeout(() => {
      setSteps(prev => prev.map(s => {
        if (s.id === "fact-check") return { ...s, status: "completed" };
        if (s.id === "score") return { ...s, status: "running" };
        return s;
      }));
    }, 4500);

    // Finish
    setTimeout(() => {
      setSteps(prev => prev.map(s => s.id === "score" ? { ...s, status: "completed" } : s));
      setIsAnalyzing(false);
      setShowResult(true);

      // Mock result based on content length or some random logic for demo
      const isDangerous = content.includes("http") || content.toLowerCase().includes("trúng thưởng");
      
      if (isDangerous) {
        setVerdict({
          score: 85,
          level: "MALICIOUS",
          reason: "Đường dẫn trỏ đến một tên miền (Domain) mới đăng ký cách đây 2 ngày và bị gắn cờ lừa đảo (phishing) bởi 3 công cụ bảo mật trên VirusTotal. Tin nhắn dùng chiêu trò mạo danh thương hiệu.",
          recommendation: "Tuyệt đối KHÔNG NHẤP VÀO LINK hoặc cung cấp thông tin cá nhân. Hãy xóa tin nhắn này ngay lập tức.",
          limitations: hasConsent ? undefined : ["Không thể quét link chi tiết vì người dùng không cấp quyền (Consent) quét bên ngoài."]
        });
      } else {
        setVerdict({
          score: 15,
          level: "SAFE",
          reason: "Nội dung tin nhắn và các đường link đính kèm không có dấu hiệu lừa đảo. Không tìm thấy trong danh sách đen.",
          recommendation: "Tin nhắn này an toàn để đọc. Tuy nhiên, luôn cảnh giác với các yêu cầu chuyển tiền hoặc thông tin nhạy cảm.",
        });
      }
    }, 6000);
  };

  return (
    <div className="min-h-screen py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-12">
        
        {/* Header Section */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center p-3 bg-primary/10 rounded-full mb-4">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-foreground">
            AI PROTECT <span className="text-primary">Scanner</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Hệ thống nhận diện tin giả và cảnh báo đường link lừa đảo theo thời gian thực.
          </p>
        </div>

        {/* Input Section */}
        {!isAnalyzing && !showResult && (
          <div className="fade-in">
            <SmartInput onSubmit={simulateAnalysis} isLoading={isAnalyzing} />
          </div>
        )}

        {/* Progress Section */}
        {isAnalyzing && (
          <div className="fade-in">
            <ProgressStepper steps={steps} />
          </div>
        )}

        {/* Result Section */}
        {showResult && verdict && (
          <div className="fade-in space-y-8">
            <VerdictCard {...verdict} />
            
            <div className="text-center">
              <button
                onClick={() => {
                  setShowResult(false);
                  setVerdict(null);
                }}
                className="px-6 py-2 rounded-full border border-border text-foreground hover:bg-secondary transition-colors"
              >
                Kiểm tra tin nhắn khác
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
