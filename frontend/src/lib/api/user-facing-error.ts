const MESSAGES: Record<string, string> = {
  API_CONFIGURATION_ERROR: "Dịch vụ kiểm tra hiện chưa sẵn sàng. Vui lòng thử lại sau.",
  NETWORK_ERROR: "Không thể kết nối dịch vụ kiểm tra. Vui lòng kiểm tra kết nối và thử lại.",
  VALIDATION_ERROR: "Dữ liệu gửi lên chưa hợp lệ. Vui lòng kiểm tra và thử lại.",
  FORBIDDEN: "Bạn không có quyền thực hiện thao tác này.",
  NOT_FOUND: "Nội dung bạn yêu cầu không còn khả dụng.",
  RATE_LIMITED: "Bạn đã thao tác quá nhanh. Vui lòng thử lại sau ít phút.",
  PROVIDER_TIMEOUT: "Dịch vụ kiểm tra đang phản hồi chậm. Vui lòng thử lại.",
  CONFLICT: "Dữ liệu vừa thay đổi. Vui lòng tải lại và thử lại.",
  INTERNAL_ERROR: "Dịch vụ kiểm tra gặp sự cố tạm thời. Vui lòng thử lại.",
  HTTP_ERROR: "Không thể hoàn tất yêu cầu. Vui lòng thử lại.",
};

/** Never render a server, provider, or browser exception verbatim in the UI. */
export function userFacingErrorMessage(code: string, retryable = false): string {
  return MESSAGES[code] ?? (retryable
    ? "Dịch vụ kiểm tra đang tạm thời không khả dụng. Vui lòng thử lại."
    : "Không thể hoàn tất yêu cầu. Vui lòng thử lại hoặc liên hệ quản trị viên.");
}
