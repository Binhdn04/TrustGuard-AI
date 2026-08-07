import type {
  AnalysisAcceptedResponse,
  AnalysisApi,
  AnalysisCreateRequest,
  AnalysisViewModel,
} from "@/types/analysis";

interface MockRecord {
  request: AnalysisCreateRequest;
  createdAt: string;
  polls: number;
}

const records = new Map<string, MockRecord>();

function runningResponse(
  analysisId: string,
  record: MockRecord,
): AnalysisViewModel {
  return {
    id: analysisId,
    status: "running",
    originalContent: record.request.message,
    createdAt: record.createdAt,
    completedAt: null,
    factCheck: null,
    linkSafety: {
      status: "running",
      overallVerdict: null,
      urls: [],
      limitations: [],
    },
    limitations: [],
  };
}

function completedResponse(
  analysisId: string,
  record: MockRecord,
): AnalysisViewModel {
  const { message, consent_to_scan_urls } = record.request;
  const msgLower = message.toLocaleLowerCase("vi");
  const completedAt = new Date().toISOString();
  
  const base: AnalysisViewModel = {
    id: analysisId,
    status: "completed",
    originalContent: message,
    createdAt: record.createdAt,
    completedAt,
    factCheck: null,
    linkSafety: {
      status: "not_applicable",
      overallVerdict: null,
      urls: [],
      limitations: [],
    },
    limitations: [],
  };

  const hasUrl = /https?:\/\/[^\s]+/giu.test(message);
  const matchedUrls = message.match(/https?:\/\/[^\s]+/giu) || [];

  // Link safety base
  if (hasUrl) {
    if (!consent_to_scan_urls) {
      base.linkSafety.status = "not_scanned";
    } else {
      base.linkSafety.status = "completed";
      base.linkSafety.urls = matchedUrls.map(url => ({
        url,
        normalizedUrl: url,
        verdict: "safe",
        provider: "Mock URL Scanner",
        signals: ["Domain uy tín"],
        domainRegisteredAt: "2020-01-01T00:00:00Z",
        redirects: [],
        observedAt: completedAt,
      }));
      base.linkSafety.overallVerdict = "safe";
    }
  }

  // 1. Claim bị bác bỏ, không có URL
  if (msgLower.includes("cấm hoàn toàn xe máy")) {
    base.factCheck = {
      overallStance: "refutes",
      summary: "Thông tin này sai sự thật. Chưa có chính sách chính thức nào cấm hoàn toàn xe máy vào năm 2027.",
      confidence: 0.9,
      claims: [
        {
          id: "claim-1",
          text: "Việt Nam sẽ cấm hoàn toàn xe máy từ năm 2027.",
          stance: "refutes",
          confidence: 0.95,
          explanation: "Bộ Giao thông Vận tải đã bác bỏ thông tin cấm hoàn toàn xe máy. Thay vào đó là lộ trình hạn chế dần tại các khu vực trung tâm.",
          sources: [
            {
              id: "src-1",
              publisher: "Báo Chính Phủ",
              title: "Bộ GTVT bác tin đồn cấm xe máy năm 2027",
              url: "https://baochinhphu.vn",
              finding: "Bác bỏ tin đồn",
              relevance: 1.0,
              observedAt: completedAt,
              official: true,
            }
          ]
        }
      ]
    };
    return base;
  }

  // 2. Claim được xác nhận
  if (msgLower.includes("uống đủ nước")) {
    base.factCheck = {
      overallStance: "supports",
      summary: "Thông tin chính xác và có cơ sở khoa học.",
      confidence: 0.95,
      claims: [
        {
          id: "claim-2",
          text: "Uống đủ 2 lít nước mỗi ngày tốt cho sức khỏe.",
          stance: "supports",
          confidence: 0.99,
          explanation: "Nhiều tổ chức y tế khuyến cáo uống đủ nước để duy trì các chức năng cơ thể.",
          sources: [
            {
              id: "src-2",
              publisher: "Tổ chức Y tế Thế giới",
              title: "Khuyến nghị về lượng nước hằng ngày",
              url: "https://who.int",
              finding: "Xác nhận",
              relevance: 0.9,
              observedAt: completedAt,
              official: true,
            }
          ]
        }
      ]
    };
    return base;
  }

  // 3. Nhiều claim có kết luận mixed
  if (msgLower.includes("nước chanh")) {
    base.factCheck = {
      overallStance: "mixed",
      summary: "Bài đăng chứa một số thông tin đúng nhưng đi kèm với tuyên bố sai sự thật về y khoa.",
      confidence: 0.85,
      claims: [
        {
          id: "claim-3a",
          text: "Nước chanh cung cấp nhiều vitamin C.",
          stance: "supports",
          confidence: 0.99,
          explanation: "Chanh là loại quả giàu Vitamin C.",
          sources: []
        },
        {
          id: "claim-3b",
          text: "Nước chanh chữa khỏi ung thư.",
          stance: "refutes",
          confidence: 0.95,
          explanation: "Không có bằng chứng y khoa nào chứng minh nước chanh chữa được ung thư.",
          sources: [
            {
              id: "src-3",
              publisher: "Viện Ung thư Quốc gia",
              title: "Thực hư chuyện nước chanh chữa ung thư",
              url: "https://cancer.gov",
              finding: "Bác bỏ",
              relevance: 1.0,
              observedAt: completedAt,
              official: true,
            }
          ]
        }
      ]
    };
    return base;
  }

  // 4. Không tìm thấy nguồn, kết quả unrated
  if (msgLower.includes("người ngoài hành tinh")) {
    base.factCheck = {
      overallStance: "unrated",
      summary: "Chưa có đủ bằng chứng xác thực để kết luận.",
      confidence: 0.2,
      claims: [
        {
          id: "claim-4",
          text: "Người ngoài hành tinh vừa đáp xuống bãi cỏ.",
          stance: "unrated",
          confidence: 0.1,
          explanation: "Không tìm thấy báo cáo hoặc bằng chứng đáng tin cậy nào về sự kiện này.",
          sources: []
        }
      ]
    };
    base.limitations.push("Không tìm thấy dữ liệu trong cơ sở kiểm chứng.");
    return base;
  }

  // 5. Claim bị bác bỏ và URL nguy hiểm
  if (msgLower.includes("trúng thưởng") && hasUrl) {
    base.factCheck = {
      overallStance: "refutes",
      summary: "Đây là thông tin lừa đảo.",
      confidence: 0.95,
      claims: [
        {
          id: "claim-5",
          text: "Bạn đã trúng thưởng iPhone 15.",
          stance: "refutes",
          confidence: 0.9,
          explanation: "Đây là mẫu tin nhắn lừa đảo phổ biến.",
          sources: []
        }
      ]
    };
    if (consent_to_scan_urls) {
      base.linkSafety.overallVerdict = "malicious";
      base.linkSafety.urls = matchedUrls.map(url => ({
        url,
        normalizedUrl: url,
        verdict: "malicious",
        provider: "Mock Security",
        signals: ["Phishing", "Blacklisted"],
        domainRegisteredAt: "2023-01-01T00:00:00Z",
        redirects: [],
        observedAt: completedAt,
      }));
    }
    return base;
  }

  // 7. URL scan thất bại nhưng fact-check vẫn hoàn thành
  if (msgLower.includes("lỗi url")) {
    base.factCheck = {
      overallStance: "supports",
      summary: "Fact check hoàn thành bình thường.",
      confidence: 0.9,
      claims: [
        {
          id: "claim-7",
          text: "Một tuyên bố bình thường.",
          stance: "supports",
          confidence: 0.9,
          explanation: "Đúng sự thật.",
          sources: []
        }
      ]
    };
    if (consent_to_scan_urls && hasUrl) {
      base.linkSafety.status = "failed";
      base.linkSafety.limitations.push("Dịch vụ kiểm tra URL đang bảo trì.");
    }
    return base;
  }

  // 8. Toàn bộ analysis thất bại
  if (msgLower.includes("fail analysis")) {
    base.status = "failed";
    return base;
  }

  // 10. Kết quả có nhiều nguồn và limitation
  if (msgLower.includes("phức tạp")) {
    base.factCheck = {
      overallStance: "mixed",
      summary: "Vấn đề này đang gây tranh cãi và có nhiều luồng thông tin khác nhau.",
      confidence: 0.7,
      claims: [
        {
          id: "claim-10",
          text: "Một sự kiện kinh tế đang tranh cãi.",
          stance: "mixed",
          confidence: 0.6,
          explanation: "Có nhiều nguồn đưa ra nhận định trái chiều.",
          sources: [
            {
              id: "src-10a",
              publisher: "Báo A",
              title: "Nhận định A",
              url: "https://baoa.example",
              finding: "Nghiêng về ủng hộ",
              relevance: 0.8,
              observedAt: completedAt,
              official: false,
            },
            {
              id: "src-10b",
              publisher: "Báo B",
              title: "Phản bác ý kiến A",
              url: "https://baob.example",
              finding: "Bác bỏ một phần",
              relevance: 0.8,
              observedAt: completedAt,
              official: false,
            }
          ]
        }
      ]
    };
    base.limitations.push("Sự việc đang tiếp diễn, thông tin có thể thay đổi.");
    base.limitations.push("Phân tích dựa trên các báo cáo tạm thời.");
    return base;
  }

  // Default fallback (mixed)
  base.factCheck = {
    overallStance: "unrated",
    summary: "Hệ thống đã ghi nhận nội dung nhưng chưa thể phân loại chính xác.",
    confidence: null,
    claims: [
      {
        id: "claim-def",
        text: message.substring(0, 50) + "...",
        stance: "unrated",
        confidence: null,
        explanation: "Chưa có đủ dữ liệu.",
        sources: []
      }
    ]
  };

  return base;
}

export class MockAnalysisApi implements AnalysisApi {
  async createAnalysis(
    request: AnalysisCreateRequest,
  ): Promise<AnalysisAcceptedResponse> {
    const analysisId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    records.set(analysisId, { request, createdAt, polls: 0 });
    return {
      contract_version: "v1",
      analysis_id: analysisId,
      status: "queued",
      created_at: createdAt,
    };
  }

  async getAnalysis(analysisId: string): Promise<AnalysisViewModel> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");

    // 9. Trạng thái queued/running kéo dài
    if (record.request.message.toLowerCase().includes("chạy lâu")) {
      record.polls += 1;
      if (record.polls < 5) return runningResponse(analysisId, record);
      return completedResponse(analysisId, record);
    }

    record.polls += 1;
    if (record.polls < 2) return runningResponse(analysisId, record);
    return completedResponse(analysisId, record);
  }
}

export function resetMockAnalyses(): void {
  records.clear();
}
