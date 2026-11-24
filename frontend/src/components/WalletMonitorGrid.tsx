"use client";

import React from "react";
import { Wallet as WalletIcon } from "lucide-react";
import { formatVnd, Wallet } from "@/lib/api";

interface WalletMonitorGridProps {
  wallets: Wallet[];
}

export function WalletMonitorGrid({ wallets }: WalletMonitorGridProps) {
  return (
    <div className="xl:col-span-7 grid grid-cols-2 sm:grid-cols-5 gap-2">
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
              <span className="text-slate-500 font-mono">{w.owner_id}</span>
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
          </div>
        );
      })}
    </div>
  );
}
