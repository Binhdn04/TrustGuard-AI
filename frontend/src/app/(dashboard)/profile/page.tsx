"use client";

import { useAuth } from "@/lib/auth-context";
import { User, Mail, Shield, Key } from "lucide-react";

export default function ProfilePage() {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Hồ sơ cá nhân</h1>
        <p className="text-sm text-muted-foreground mt-1">Quản lý thông tin tài khoản và cài đặt bảo mật</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1 space-y-2">
          <button className="w-full flex items-center px-4 py-3 bg-primary/10 text-primary rounded-xl font-medium">
            <User className="w-5 h-5 mr-3" />
            Thông tin chung
          </button>
          <button className="w-full flex items-center px-4 py-3 text-muted-foreground hover:bg-secondary hover:text-foreground rounded-xl font-medium transition-colors">
            <Key className="w-5 h-5 mr-3" />
            Đổi mật khẩu
          </button>
        </div>

        <div className="md:col-span-2">
          <div className="bg-card border border-border rounded-xl p-6 space-y-6">
            <div className="flex items-center gap-4 border-b border-border pb-6">
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-primary/10 text-primary text-2xl font-bold">
                {user.name.charAt(0)}
              </div>
              <div>
                <h2 className="text-xl font-semibold text-foreground">{user.name}</h2>
                <div className="flex items-center text-sm text-muted-foreground mt-1">
                  <Shield className="w-4 h-4 mr-1 text-emerald-500" />
                  Quyền: {user.role === "security_admin" ? "Admin Hệ thống" : "Người dùng"}
                </div>
              </div>
            </div>

            <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Họ và Tên</label>
                  <div className="relative">
                    <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <input 
                      type="text" 
                      defaultValue={user.name}
                      className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary outline-none transition-all"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground">Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <input 
                      type="email" 
                      defaultValue={user.email}
                      disabled
                      className="w-full pl-9 pr-4 py-2 bg-muted border border-border rounded-lg opacity-70 cursor-not-allowed"
                    />
                  </div>
                </div>
              </div>
              
              <div className="pt-4 flex justify-end">
                <button className="px-4 py-2 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition-colors">
                  Lưu thay đổi
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
