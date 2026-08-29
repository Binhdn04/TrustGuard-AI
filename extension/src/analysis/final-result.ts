import type {
  AnalysisSnapshot,
  RecommendedAction,
  ScopeDecision,
  SecurityRisk,
} from "../api/client";

const RISK_LABELS: Readonly<Record<SecurityRisk, string>> = {
  SAFE: "Chưa phát hiện rủi ro",
  LOW_RISK: "Rủi ro thấp",
  SUSPICIOUS: "Đáng ngờ",
  HIGH_RISK: "Rủi ro cao",
  MALICIOUS: "Độc hại",
  INSUFFICIENT_EVIDENCE: "Chưa đủ bằng chứng",
};

const ACTION_LABELS: Readonly<Record<RecommendedAction, string>> = {
  DO_NOT_OPEN_LINK: "Không mở liên kết này",
  DO_NOT_SHARE_CREDENTIALS: "Không cung cấp thông tin đăng nhập",
  DO_NOT_SHARE_OTP: "Không cung cấp mã OTP",
  DO_NOT_TRANSFER_MONEY: "Không chuyển tiền",
  VERIFY_VIA_OFFICIAL_CHANNEL: "Xác minh qua kênh chính thức",
  CHANGE_PASSWORD_IF_ALREADY_SHARED: "Đổi mật khẩu nếu đã chia sẻ",
  CONTACT_BANK_IF_ALREADY_PAID: "Liên hệ ngân hàng nếu đã thanh toán",
  REPORT_AND_BLOCK_SENDER: "Báo cáo và chặn người gửi",
  PROCEED_WITH_CAUTION: "Chỉ tiếp tục khi đã xác minh",
  ALLOW_OPEN: "Có thể mở sau khi tự kiểm tra đích đến",
  CLOSE_PAGE_AND_DO_NOT_RETURN: "Đóng trang và không truy cập lại",
  CHANGE_PASSWORD_FROM_TRUSTED_DEVICE: "Đổi mật khẩu từ thiết bị tin cậy",
  REVOKE_ACTIVE_SESSIONS: "Thu hồi các phiên đăng nhập đang hoạt động",
  CONTACT_BANK_OR_PAYMENT_PROVIDER: "Liên hệ ngân hàng hoặc đơn vị thanh toán",
  PRESERVE_MESSAGE_FOR_REPORTING: "Giữ lại tin nhắn để báo cáo",
};

const SCOPE_LABELS: Readonly<Record<ScopeDecision, string>> = {
  IN_SCOPE: "Trong phạm vi Security Triage",
  NEED_MORE_INFO: "Cần thêm thông tin",
  OUT_OF_SCOPE_GENERAL_FACT_CHECK: "Ngoài phạm vi kiểm tra bảo mật",
};

export type FinalResultTone = "safe" | "caution" | "danger" | "neutral";

export interface FinalResultView {
  analysisId: string;
  title: string;
  scopeLabel: string;
  riskLabel: string | null;
  tone: FinalResultTone;
  score: number | null;
  confidencePercent: number | null;
  summary: string;
  actions: string[];
  limitations: string[];
  degraded: boolean;
  failed: boolean;
}

function toneFor(risk: SecurityRisk | null): FinalResultTone {
  if (risk === "SAFE" || risk === "LOW_RISK") return "safe";
  if (risk === "SUSPICIOUS" || risk === "INSUFFICIENT_EVIDENCE") return "caution";
  if (risk === "HIGH_RISK" || risk === "MALICIOUS") return "danger";
  return "neutral";
}

export function finalResultView(snapshot: AnalysisSnapshot): FinalResultView | null {
  if (!snapshot.terminal || snapshot.result === null) return null;
  const result = snapshot.result;
  if (snapshot.status === "failed") {
    return {
      analysisId: snapshot.analysisId,
      title: "Không thể hoàn tất phân tích",
      scopeLabel: SCOPE_LABELS[result.scopeDecision],
      riskLabel: null,
      tone: "neutral",
      score: null,
      confidencePercent: null,
      summary: "Backend xác nhận lượt phân tích đã thất bại. Không sử dụng progress trước đó làm kết luận rủi ro.",
      actions: [],
      limitations: result.limitations,
      degraded: true,
      failed: true,
    };
  }

  let title = "Kết quả kiểm tra bảo mật";
  let summary = result.summary ?? "TrustGuard chưa cung cấp bản tóm tắt ngắn.";
  if (result.scopeDecision === "NEED_MORE_INFO") {
    title = "Cần thêm thông tin";
    summary = result.followUpQuestion ?? "Cần bổ sung ngữ cảnh trước khi đánh giá rủi ro.";
  } else if (result.scopeDecision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") {
    title = "Ngoài phạm vi Security Triage";
    summary = result.boundaryMessage ?? "Yêu cầu này không thuộc phạm vi đánh giá an toàn tin nhắn hoặc liên kết.";
  }

  return {
    analysisId: snapshot.analysisId,
    title,
    scopeLabel: SCOPE_LABELS[result.scopeDecision],
    riskLabel: result.scopeDecision === "IN_SCOPE" && result.risk !== null ? RISK_LABELS[result.risk] : null,
    tone: result.scopeDecision === "IN_SCOPE" ? toneFor(result.risk) : "neutral",
    score: result.scopeDecision === "IN_SCOPE" ? result.score : null,
    confidencePercent:
      result.scopeDecision === "IN_SCOPE" && result.confidence !== null
        ? Math.round(result.confidence * 100)
        : null,
    summary,
    actions: result.scopeDecision === "IN_SCOPE"
      ? result.recommendedActions.map((action) => ACTION_LABELS[action])
      : [],
    limitations: result.limitations,
    degraded: result.degraded,
    failed: false,
  };
}
