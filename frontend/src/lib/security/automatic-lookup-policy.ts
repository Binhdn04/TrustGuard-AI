import type { SecurityConsentV4 } from "@/types/generated/api-v4";

export const AUTOMATIC_LOOKUP_CONSENT = {
  external_url_lookup: true,
  official_source_lookup: true,
} as const satisfies SecurityConsentV4;

export const AUTOMATIC_LOOKUP_DISCLOSURE =
  "Khi gửi, TrustGuard có thể kiểm tra liên kết bằng dịch vụ bảo mật.";

export const OFFICIAL_SOURCE_LOOKUP_DISCLOSURE =
  "Có thể đối chiếu nguồn công khai; không gửi mật khẩu, OTP hoặc token.";
