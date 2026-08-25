"use client";

import Link from "next/link";
import { useState, type FormEvent, type ReactNode } from "react";
import { useTheme } from "next-themes";
import {
  Archive,
  BellRing,
  Check,
  Eye,
  History,
  Languages,
  LogOut,
  Mail,
  Palette,
  RotateCcw,
  ShieldCheck,
  SlidersHorizontal,
  UserRound,
} from "lucide-react";

import {
  avatarToneClass,
  useAccountPreferences,
  type AvatarTone,
  type MotionPreference,
} from "@/lib/account-preferences-context";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";

export type AccountTab = "profile" | "preferences" | "privacy";

const tabs: Array<{ id: AccountTab; label: string; icon: typeof UserRound }> = [
  { id: "profile", label: "Hồ sơ", icon: UserRound },
  { id: "preferences", label: "Tùy chọn", icon: SlidersHorizontal },
  { id: "privacy", label: "Quyền riêng tư", icon: ShieldCheck },
];

const tones: AvatarTone[] = ["emerald", "blue", "violet", "amber"];

export function AccountSettings({ initialTab = "profile" }: { initialTab?: AccountTab }) {
  const { user, logout } = useAuth();
  const { preferences, updatePreferences, resetPreferences } = useAccountPreferences();
  const { theme = "system", setTheme } = useTheme();
  const [tab, setTab] = useState<AccountTab>(initialTab);
  const [saved, setSaved] = useState(false);

  if (!user) return null;
  const displayName = preferences.displayName || user.name;

  const saveProfile = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    updatePreferences({
      displayName: String(data.get("displayName") ?? user.name),
      avatarTone: String(data.get("avatarTone") ?? "emerald") as AvatarTone,
    });
    setSaved(true);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="border-b border-border/70 pb-6">
        <p className="micro-label text-primary">TÀI KHOẢN / TÙY CHỌN THIẾT BỊ</p>
        <h1 className="mt-2 text-3xl font-bold tracking-[-0.025em]">Tài khoản và cài đặt</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
          Quản lý hồ sơ hiển thị và trải nghiệm trên thiết bị này. Danh tính và quyền truy cập vẫn do hệ thống đăng nhập xác minh.
        </p>
      </header>

      <div className="grid items-start gap-6 lg:grid-cols-[15rem_minmax(0,1fr)]">
        <nav aria-label="Mục cài đặt tài khoản" className="rounded-2xl border border-border bg-card p-2">
          {tabs.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                type="button"
                aria-current={tab === item.id ? "page" : undefined}
                onClick={() => { setTab(item.id); setSaved(false); }}
                className={cn(
                  "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm font-semibold transition-colors",
                  tab === item.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="size-4" aria-hidden="true" />{item.label}
              </button>
            );
          })}
        </nav>

        <section className="min-w-0 rounded-2xl border border-border bg-card p-5 shadow-sm sm:p-7">
          {tab === "profile" && (
            <form onSubmit={saveProfile} className="space-y-6">
              <div className="flex flex-col gap-4 border-b border-border pb-6 sm:flex-row sm:items-center">
                <div className={cn("grid size-20 shrink-0 place-items-center rounded-2xl border text-2xl font-bold uppercase", avatarToneClass[preferences.avatarTone])}>
                  {displayName.charAt(0)}
                </div>
                <div>
                  <p className="micro-label">Hồ sơ hiển thị</p>
                  <h2 className="mt-1 text-xl font-bold">{displayName}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{user.email}</p>
                </div>
              </div>

              <div className="grid gap-5 sm:grid-cols-2">
                <div className="space-y-2 text-sm font-semibold">
                  <label htmlFor="account-display-name">Tên hiển thị</label>
                  <span className="relative block">
                    <UserRound className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
                    <input id="account-display-name" name="displayName" defaultValue={displayName} maxLength={80} className="w-full rounded-xl border border-input bg-background py-2.5 pl-9 pr-3 font-normal" />
                  </span>
                  <span className="block text-xs font-normal text-muted-foreground">MVP lưu tên hiển thị trên trình duyệt; không sửa claim từ OIDC.</span>
                </div>
                <div className="space-y-2 text-sm font-semibold">
                  <label htmlFor="account-email">Email</label>
                  <span className="relative block">
                    <Mail className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
                    <input id="account-email" value={user.email} readOnly aria-readonly="true" className="w-full cursor-not-allowed rounded-xl border border-border bg-muted py-2.5 pl-9 pr-3 font-normal text-muted-foreground" />
                  </span>
                  <span className="block text-xs font-normal text-muted-foreground">Email được quản lý bởi nhà cung cấp đăng nhập.</span>
                </div>
              </div>

              <fieldset>
                <legend className="text-sm font-semibold">Màu avatar</legend>
                <div className="mt-3 flex flex-wrap gap-3">
                  {tones.map((tone) => (
                    <label key={tone} className="cursor-pointer">
                      <input aria-label={tone} className="peer sr-only" type="radio" name="avatarTone" value={tone} defaultChecked={preferences.avatarTone === tone} />
                      <span className={cn("grid size-11 place-items-center rounded-xl border text-sm font-bold uppercase ring-offset-2 ring-offset-card peer-checked:ring-2 peer-checked:ring-ring", avatarToneClass[tone])}>{displayName.charAt(0)}</span>
                      <span className="sr-only">{tone}</span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5">
                <p className="text-xs text-muted-foreground">Vai trò: <strong className="text-foreground">{user.role === "security_admin" ? "Quản trị bảo mật" : "Người dùng"}</strong></p>
                <div className="flex items-center gap-3">
                  {saved && <span role="status" className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 dark:text-emerald-300"><Check className="size-3.5" />Đã lưu</span>}
                  <button type="submit" className="rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground">Lưu hồ sơ</button>
                </div>
              </div>
            </form>
          )}

          {tab === "preferences" && (
            <div className="space-y-6">
              <div><p className="micro-label">Trải nghiệm</p><h2 className="mt-1 text-xl font-bold">Tùy chọn giao diện</h2></div>
              <PreferenceRow icon={Palette} title="Giao diện" description="Áp dụng ngay cho toàn bộ workspace.">
                <select aria-label="Giao diện" value={theme} onChange={(event) => setTheme(event.target.value)} className="rounded-xl border border-input bg-background px-3 py-2 text-sm">
                  <option value="system">Theo hệ thống</option><option value="light">Sáng</option><option value="dark">Tối</option>
                </select>
              </PreferenceRow>
              <PreferenceRow icon={Eye} title="Mức chi tiết mặc định" description="Chỉ thay đổi cách trình bày; không thay đổi kế hoạch, công cụ hay chính sách rủi ro.">
                <select aria-label="Mức chi tiết mặc định" value={preferences.defaultPresentation} onChange={(event) => updatePreferences({ defaultPresentation: event.target.value as "simple" | "analyst" })} className="rounded-xl border border-input bg-background px-3 py-2 text-sm">
                  <option value="simple">Đơn giản</option><option value="analyst">Kỹ thuật</option>
                </select>
              </PreferenceRow>
              <PreferenceRow icon={BellRing} title="Chuyển động" description="Giảm animation nếu bạn muốn giao diện ổn định hơn.">
                <select aria-label="Chuyển động" value={preferences.motion} onChange={(event) => updatePreferences({ motion: event.target.value as MotionPreference })} className="rounded-xl border border-input bg-background px-3 py-2 text-sm">
                  <option value="system">Theo hệ thống</option><option value="reduced">Giảm chuyển động</option>
                </select>
              </PreferenceRow>
              <PreferenceRow icon={Languages} title="Ngôn ngữ" description="Bản MVP hiện cung cấp giao diện tiếng Việt.">
                <span className="rounded-xl border border-border bg-muted px-3 py-2 text-sm text-muted-foreground">Tiếng Việt</span>
              </PreferenceRow>
            </div>
          )}

          {tab === "privacy" && (
            <div className="space-y-6">
              <div><p className="micro-label">Quyền riêng tư và truy cập</p><h2 className="mt-1 text-xl font-bold">Dữ liệu và phiên đăng nhập</h2></div>
              <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/8 p-4 text-sm leading-6">
                <ShieldCheck className="mb-2 size-5 text-emerald-700 dark:text-emerald-300" />
                Lịch sử chỉ được đọc theo chủ sở hữu. Đồng ý cho DNS, redirect, RDAP và kiểm tra uy tín URL luôn được hỏi theo từng yêu cầu và không được lưu thành đồng ý mặc định tại đây.
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Link href="/history" className="rounded-xl border border-border p-4 transition-colors hover:bg-muted/60"><History className="size-5 text-primary" /><strong className="mt-3 block text-sm">Lịch sử kiểm tra</strong><span className="mt-1 block text-xs leading-5 text-muted-foreground">Xem các lượt kiểm tra thuộc tài khoản hiện tại.</span></Link>
                <Link href="/history" className="rounded-xl border border-border p-4 transition-colors hover:bg-muted/60"><Archive className="size-5 text-primary" /><strong className="mt-3 block text-sm">Báo cáo của tôi</strong><span className="mt-1 block text-xs leading-5 text-muted-foreground">Mở lượt kiểm tra tương ứng để xem trạng thái báo cáo và khiếu nại.</span></Link>
              </div>
              <div className="flex flex-col gap-3 border-t border-border pt-5 sm:flex-row sm:justify-between">
                <button type="button" onClick={() => { resetPreferences(); setTheme("system"); }} className="inline-flex items-center justify-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-semibold"><RotateCcw className="size-4" />Đặt lại tùy chọn</button>
                <button type="button" onClick={logout} className="inline-flex items-center justify-center gap-2 rounded-xl border border-destructive/30 px-4 py-2.5 text-sm font-semibold text-destructive hover:bg-destructive/10"><LogOut className="size-4" />Đăng xuất</button>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function PreferenceRow({ icon: Icon, title, description, children }: { icon: typeof Palette; title: string; description: string; children: ReactNode }) {
  return <div className="flex flex-col gap-4 rounded-xl border border-border p-4 sm:flex-row sm:items-center sm:justify-between"><div className="flex min-w-0 gap-3"><span className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary"><Icon className="size-4" /></span><div><h3 className="text-sm font-semibold">{title}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p></div></div><div className="shrink-0">{children}</div></div>;
}
