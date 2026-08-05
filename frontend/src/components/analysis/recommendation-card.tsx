import { AlertIcon, CheckIcon, ShieldIcon } from "@/components/ui/icons";
import type { RecommendedAction } from "@/types/analysis";

const recommendations: Record<
  RecommendedAction,
  { title: string; description: string; style: string }
> = {
  allow: {
    title: "Có thể tiếp tục thận trọng",
    description: "Không phát hiện rủi ro đáng kể, nhưng hãy luôn kiểm tra địa chỉ trước khi nhập thông tin.",
    style: "bg-emerald-600",
  },
  show_caution: {
    title: "Hãy kiểm tra thêm trước khi tiếp tục",
    description: "Không cung cấp thông tin cá nhân và ưu tiên mở ứng dụng hoặc website chính thức.",
    style: "bg-amber-500",
  },
  do_not_open: {
    title: "Không mở hoặc tương tác với liên kết",
    description: "Không đăng nhập, tải tệp hay cung cấp OTP. Hãy xóa tin nhắn nếu bạn không nhận diện người gửi.",
    style: "bg-orange-600",
  },
  escalate_for_review: {
    title: "Không mở liên kết — đã chuyển đội an ninh",
    description: "Giữ nguyên tin nhắn làm bằng chứng và chờ kết quả review trước khi thực hiện bất kỳ hành động nào.",
    style: "bg-rose-600",
  },
};

export function RecommendationCard({ action }: { action: RecommendedAction }) {
  const recommendation = recommendations[action];
  const Icon = action === "allow" ? CheckIcon : action === "show_caution" ? ShieldIcon : AlertIcon;

  return (
    <section className={`rounded-3xl p-5 text-white sm:p-7 ${recommendation.style}`}>
      <div className="flex gap-4">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-white/15">
          <Icon className="size-5" />
        </span>
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.12em] text-white/70">Khuyến nghị</p>
          <h2 className="mt-2 text-lg font-bold">{recommendation.title}</h2>
          <p className="mt-2 text-sm leading-6 text-white/85">{recommendation.description}</p>
        </div>
      </div>
    </section>
  );
}
