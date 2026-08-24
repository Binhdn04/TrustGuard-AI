import Link from "next/link";
import { ChevronRight, MessageSquareText } from "lucide-react";

import type {
  RequestedActionV4,
  SecurityScenarioV4,
  SecurityScopeResponseV4,
} from "@/types/generated/api-v4";

const actionTitles: Record<RequestedActionV4, string> = {
  login: "Đăng nhập qua một liên kết",
  share_otp: "Yêu cầu chia sẻ mã OTP",
  share_credentials: "Yêu cầu cung cấp thông tin đăng nhập",
  transfer_money: "Yêu cầu chuyển tiền",
  pay_fee: "Yêu cầu thanh toán một khoản phí",
  provide_personal_information: "Yêu cầu cung cấp thông tin cá nhân",
  open_link: "Kiểm tra một liên kết",
  install_app: "Yêu cầu cài đặt ứng dụng",
  share_screen: "Yêu cầu chia sẻ màn hình",
  scan_qr: "Yêu cầu quét mã QR",
  submit_form: "Yêu cầu điền biểu mẫu",
  register_or_apply: "Đăng ký hoặc nộp đơn trực tuyến",
  download_file: "Yêu cầu tải xuống tệp",
  apply_for_passport: "Làm hộ chiếu trực tuyến",
};

const scenarioTitles: Partial<Record<SecurityScenarioV4, string>> = {
  recruitment: "Kiểm tra nội dung tuyển dụng",
  promotion_prize: "Kiểm tra thông báo khuyến mãi hoặc trúng thưởng",
  charity: "Kiểm tra lời kêu gọi từ thiện",
  investment: "Kiểm tra lời mời đầu tư",
  online_task: "Kiểm tra lời mời làm nhiệm vụ trực tuyến",
  account_verification: "Kiểm tra yêu cầu xác minh tài khoản",
  payment: "Kiểm tra yêu cầu thanh toán",
  refund: "Kiểm tra thông báo hoàn tiền",
};

function compactTitle(value: string): string {
  const normalized = value.replaceAll(/\s+/g, " ").trim();
  return normalized.length > 88 ? `${normalized.slice(0, 85).trimEnd()}…` : normalized;
}

function hostname(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname.replace(/^www\./i, "") || null;
  } catch {
    return null;
  }
}

function title(item: SecurityScopeResponseV4): string {
  const claimSummary = item.official_verification?.intent.claim_summary?.trim();
  if (claimSummary) return compactTitle(claimSummary);

  const context = item.security_context;
  const subject = context?.claimed_entity?.trim() || hostname(context?.urls[0]);
  if (context?.requested_action) {
    return compactTitle(`${actionTitles[context.requested_action]}${subject ? ` liên quan đến ${subject}` : ""}`);
  }
  if (subject) return compactTitle(`Kiểm tra nội dung liên quan đến ${subject}`);
  if (context && scenarioTitles[context.scenario]) return scenarioTitles[context.scenario]!;
  if (item.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") {
    return "Câu hỏi ngoài phạm vi kiểm tra an toàn";
  }
  return "Kiểm tra nội dung đáng ngờ";
}

export function CaseList({ items }: { items: SecurityScopeResponseV4[] }) {
  return (
    <ol aria-label="Danh sách cuộc trò chuyện" className="space-y-2">
      {items.map((item) => {
        const conversationTitle = title(item);
        return (
          <li key={item.analysis_id}>
            <Link
              href={`/cases/${encodeURIComponent(item.analysis_id)}`}
              aria-label={`Mở cuộc trò chuyện: ${conversationTitle}`}
              className="group flex items-center gap-3 rounded-2xl border border-border bg-card px-4 py-3.5 transition-colors hover:border-primary/35 hover:bg-primary/[0.025] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
            >
              <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/8 text-primary">
                <MessageSquareText className="size-4.5" aria-hidden="true" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-semibold" title={conversationTitle}>{conversationTitle}</span>
                <time className="mt-1 block text-[11px] text-muted-foreground" dateTime={item.completed_at ?? item.created_at}>
                  {new Date(item.completed_at ?? item.created_at).toLocaleString("vi-VN")}
                </time>
              </span>
              <span className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-primary">
                <span className="hidden sm:inline">Xem chi tiết</span>
                <ChevronRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
              </span>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
