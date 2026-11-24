"use client";

import React from "react";
import { AlertTriangle, Wallet as WalletIcon } from "lucide-react";
import { formatVnd, Wallet } from "@/lib/api";

interface WalletMonitorGridProps {
  wallets: Wallet[];
}

const WALLET_ROLE_SHORT: Record<string, string> = {
  W_1001: "Khách VIP",
  W_1002: "Phổ thông",
  W_1003: "Merchant",
  W_1004: "Đại lý",
  W_1005: "Quỹ Đối soát",
};

export function WalletMonitorGrid({ wallets }: WalletMonitorGridProps) {
  const hasNegative = wallets.some((w) => w.balance < 0);
  const hasInflated = wallets.some((w) => w.balance > 12_000_000);

  return (
    <div className="xl:col-span-7 space-y-2">
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        {wallets.map((w) => {
          const isNegative = w.balance < 0;
          const isInflated = w.balance > 12_000_000;
          const cardStyle = isNegative
            ? "border-rose-500/70 bg-rose-500/15"
            : isInflated
            ? "border-amber-500/70 bg-amber-500/15"
            : "border-slate-800 bg-[#090f1d]";

          return (
            <div
              key={w.id}
              className={`rounded-xl border px-3 py-2 transition ${cardStyle}`}
            >
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-mono font-bold text-slate-200 flex items-center gap-1">
                  <WalletIcon className="h-3 w-3 text-sky-400" />
                  {w.id}
                </span>
                <span className="text-[10px] text-sky-300 font-medium">
                  {WALLET_ROLE_SHORT[w.id] || w.owner_id}
                </span>
              </div>
              <div
                className={`mt-1 font-mono text-xs font-bold ${
                  isNegative
                    ? "text-rose-300"
                    : isInflated
                    ? "text-amber-300"
                    : "text-emerald-300"
                }`}
              >
                {formatVnd(w.balance)}
              </div>
              {isNegative && (
                <div className="text-[10px] font-semibold text-rose-300 mt-0.5">
                  Âm ví (Race Condition!)
                </div>
              )}
              {isInflated && (
                <div className="text-[10px] font-semibold text-amber-300 mt-0.5">
                  Cộng tiền ảo (Replay!)
                </div>
              )}
            </div>
          );
        })}
      </div>

      {(hasNegative || hasInflated) && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-500/40 bg-amber-950/25 px-3 py-2 text-[11px] text-amber-100 leading-relaxed">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <strong>Tại sao ví bị {hasNegative ? "âm tiền" : "cộng tiền ảo"}?</strong>{" "}
            Đây là bằng chứng trực quan cho thấy hệ thống Payment API gốc đang bị khai thác thành công khi{" "}
            <strong>chưa bật luật bảo vệ AI</strong>. Hãy sang{" "}
            <strong className="text-sky-300">Tab 3 (Điều tra AI SOC)</strong> → bấm{" "}
            <strong className="text-emerald-300">Enforce</strong> (hoặc bật{" "}
            <strong className="text-emerald-300">Lá chắn AI</strong> ở Tab 1) → bấm{" "}
            <strong>Reset</strong> rồi bắn lại tấn công — bạn sẽ thấy số dư ví được bảo vệ nguyên vẹn 100%!
          </div>
        </div>
      )}
    </div>
  );
}
