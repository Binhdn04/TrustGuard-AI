export const AUTOMATIC_LOOKUP_CONSENT = {
  external_url_lookup: true,
  official_source_lookup: true,
} as const;

export const AUTOMATIC_LOOKUP_DISCLOSURE =
  "Khi bạn gửi, TrustGuard có thể tự đối chiếu URL/domain với dịch vụ bảo mật khi cần. Không gửi mật khẩu, mã OTP hoặc token thật.";

export const OFFICIAL_SOURCE_LOOKUP_DISCLOSURE =
  "TrustGuard có thể tìm kiếm và đối chiếu nội dung với website chính thức cho lượt gửi hiện tại.";
