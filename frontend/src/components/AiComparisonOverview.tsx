"use client";

import React from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Layers,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Shuffle,
  Sparkles,
  Wallet as WalletIcon,
} from "lucide-react";
import { formatVnd, ScaleSimulationResponse, Wallet } from "@/lib/api";

interface AiComparisonOverviewProps {
  scaleResult: ScaleSimulationResponse | null;
  wallets: Wallet[];
  activeRulesCount: number;
  loadingAction: string | null;
  onRunRandomScenario: () => void;
  onToggleAiShield: (enabled: boolean) => void;
  onInvestigate: () => void;
  onOpenCatalog: () => void;
}

const ACCOUNT_STATUS_BADGE: Record<string, { label: string; cls: string }> = {
  DRAINED: {
    label: "ÂM VÍ / RÚT CẠN",
    cls: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  },
  INFLATED: {
    label: "CỘNG TIỀN ẢO",
    cls: "bg-amber-500/20 text-amber-300 border-amber-500/50",
  },
  DATA_LEAKED: {
    label: "LỘ DỮ LIỆU VÍ",
    cls: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  },
  COMPROMISED: {
    label: "BỊ XÂM PHẠM",
    cls: "bg-rose-500/20 text-rose-300 border-rose-500/50",
  },
  SAFE: {
    label: "KHÔNG BỊ NHẮM",
    cls: "bg-slate-800 text-slate-400 border-slate-700",
  },
};

export function AiComparisonOverview({
  scaleResult,
  wallets,
  activeRulesCount,
  loadingAction,
  onRunRandomScenario,
  onToggleAiShield,
  onInvestigate,
  onOpenCatalog,
}: AiComparisonOverviewProps) {
  const aiShieldOn = activeRulesCount >= 4;
  const liveView = scaleResult?.with_ai_live;
  const fullView = scaleResult?.with_ai_full_shield;
  const noAi = scaleResult?.without_ai;

  // Use live AI metrics when at least 1 rule is active; otherwise clearly compare against Full AI Shield projection
  const showingProjected = scaleResult ? scaleResult.active_rules_count === 0 : false;
  const aiDisplay = showingProjected ? fullView : liveView;

  return (
    <div className="space-y-5">
      {/* Guided SOC Control Strip: 1-Click AI Shield Toggle + Random Scale Run + AI Investigate */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-sky-400" />
              Trung tâm So sánh Thực chiến: Không có AI vs Có FinSec AI Bảo vệ
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Chạy đồng thời hàng chục nghìn giao dịch thật trộn nhiều mũi tấn công ngẫu nhiên và theo dõi chênh lệch từng tài khoản ví.
            </p>
          </div>

          {/* 1-Click AI Shield Toggle */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => onToggleAiShield(!aiShieldOn)}
              disabled={loadingAction !== null}
              className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-bold border transition disabled:opacity-50 ${
                aiShieldOn
                  ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-200 hover:bg-emerald-500/30"
                  : "bg-rose-500/15 border-rose-500/40 text-rose-200 hover:bg-rose-500/25"
              }`}
            >
              {aiShieldOn ? (
                <>
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Lá chắn AI: ĐANG BẬT ({activeRulesCount} luật) — Bấm để Tắt
                </>
              ) : (
                <>
                  <ShieldOff className="h-4 w-4 text-rose-400" />
                  Lá chắn AI: ĐANG TẮT ({activeRulesCount}/4 luật) — Bấm Bật Ngay
                </>
              )}
            </button>
          </div>
        </div>

        {/* 3 Clear Action Steps */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          <button
            onClick={onRunRandomScenario}
            disabled={loadingAction !== null}
            className="flex items-center justify-between rounded-xl border border-sky-500/40 bg-sky-500/15 px-3.5 py-2.5 text-left hover:bg-sky-500/25 transition disabled:opacity-50"
          >
            <div>
              <div className="text-[11px] font-bold text-sky-300 uppercase tracking-wider">
                Bước 1 · Mô phỏng Quy mô lớn
              </div>
              <div className="text-xs font-semibold text-white mt-0.5">
                {loadingAction === "scale"
                  ? "Đang chạy hàng chục nghìn giao dịch..."
                  : "Chạy Ngẫu nhiên từ Kho 900 Kịch bản"}
              </div>
            </div>
            <Shuffle className="h-4 w-4 text-sky-300 shrink-0" />
          </button>

          <button
            onClick={onOpenCatalog}
            className="flex items-center justify-between rounded-xl border border-indigo-500/40 bg-indigo-500/15 px-3.5 py-2.5 text-left hover:bg-indigo-500/25 transition"
          >
            <div>
              <div className="text-[11px] font-bold text-indigo-300 uppercase tracking-wider">
                Kho 900 Kịch bản &amp; Tùy chỉnh
              </div>
              <div className="text-xs font-semibold text-white mt-0.5">
                Chọn kịch bản 2k – 60k GD / Kết hợp đa tấn công
              </div>
            </div>
            <Layers className="h-4 w-4 text-indigo-300 shrink-0" />
          </button>

          <button
            onClick={onInvestigate}
            disabled={loadingAction !== null}
            className="flex items-center justify-between rounded-xl border border-emerald-500/40 bg-emerald-500/15 px-3.5 py-2.5 text-left hover:bg-emerald-500/25 transition disabled:opacity-50"
          >
            <div>
              <div className="text-[11px] font-bold text-emerald-300 uppercase tracking-wider">
                Bước 2 · AI SOC Điều tra &amp; Xuất Báo cáo
              </div>
              <div className="text-xs font-semibold text-white mt-0.5">
                {loadingAction === "investigate"
                  ? "AI đang phân tích log & Dry-Run..."
                  : "Phân tích ReAct + Dry-Run + Xuất PDF/MD"}
              </div>
            </div>
            <Cpu className="h-4 w-4 text-emerald-300 shrink-0" />
          </button>
        </div>
      </div>

      {/* Empty state prompt before first simulation */}
      {!scaleResult ? (
        <div className="rounded-2xl border border-dashed border-slate-700 bg-[#0d1424]/70 p-8 text-center space-y-3">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-500/15 border border-sky-500/30 text-sky-400">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h3 className="text-base font-bold text-white">
            Sẵn sàng mô phỏng hàng chục nghìn giao dịch thực tế
          </h3>
          <p className="text-xs text-slate-400 max-w-xl mx-auto leading-relaxed">
            Bấm <strong className="text-sky-300">Chạy Ngẫu nhiên từ Kho 900 Kịch bản</strong> để hệ thống phát sinh
            10.000 – 60.000 giao dịch trộn ngẫu nhiên nhiều kiểu tấn công cùng lúc và so sánh trực quan thiệt hại giữa{" "}
            <strong className="text-rose-300">Không có AI</strong> và{" "}
            <strong className="text-emerald-300">Có FinSec AI bảo vệ</strong> cho từng tài khoản ({wallets.length} ví).
          </p>
          <button
            onClick={onRunRandomScenario}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-500 px-5 py-2.5 text-xs font-bold text-white shadow-lg hover:from-sky-400 hover:to-indigo-400 transition"
          >
            <Shuffle className="h-4 w-4" />
            Chạy Kịch bản Mẫu Ngay
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      ) : (
        <>
          {/* Scenario Context Banner */}
          <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md bg-sky-500/20 border border-sky-500/40 px-2 py-0.5 font-mono text-[11px] font-bold text-sky-300">
                  {scaleResult.scenario.id}
                </span>
                <span className="text-sm font-bold text-white">
                  {scaleResult.scenario.name}
                </span>
              </div>
              <div className="text-xs text-slate-400">
                Tổng lưu lượng:{" "}
                <strong className="text-white font-mono">
                  {scaleResult.total_transactions.toLocaleString("vi-VN")} giao dịch
                </strong>{" "}
                ({scaleResult.clean_transactions.toLocaleString("vi-VN")} khách thật ·{" "}
                <span className="text-rose-300 font-semibold">
                  {scaleResult.attack_transactions.toLocaleString("vi-VN")} tấn công ({scaleResult.attack_ratio_pct}%)
                </span>
                ) · Xử lý trong{" "}
                <span className="font-mono text-sky-300">{scaleResult.simulation_time_ms}ms</span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {scaleResult.vector_breakdown.map((v) => (
                <span
                  key={v.vector}
                  className="rounded-full bg-slate-900 border border-slate-700 px-2.5 py-0.5 text-[11px] font-mono text-slate-300"
                >
                  {v.vector}
                </span>
              ))}
              {scaleResult.with_prompt_injection && (
                <span className="rounded-full bg-fuchsia-500/20 border border-fuchsia-500/40 px-2.5 py-0.5 text-[11px] font-bold text-fuchsia-200">
                  + Prompt Injection
                </span>
              )}
            </div>
          </div>

          {/* SIDE-BY-SIDE HERO COMPARISON: TRADITIONAL BANK SECURITY vs TRADITIONAL + FINSEC AI */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* LEFT: TRADITIONAL STATIC SECURITY (NO AI) */}
            <div className="rounded-2xl border border-amber-500/40 bg-gradient-to-br from-rose-950/30 via-[#0d1424] to-[#0d1424] p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-300">
                    <ShieldAlert className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-amber-200">
                      BẢO MẬT NGÂN HÀNG TRUYỀN THỐNG (5 Lớp Tĩnh · Không AI)
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      WAF, Rate Limit, IAM/RBAC, App/DB Guard &amp; SIEM tĩnh — chặn ~70–80%, vẫn lọt lỗ hổng logic zero-day
                    </p>
                  </div>
                </div>
                <span className="rounded-full bg-amber-500/20 border border-amber-500/40 px-2.5 py-0.5 text-[11px] font-bold text-amber-200 whitespace-nowrap">
                  {noAi?.block_rate_pct ?? 60}% CHẶN · LỌT {(100 - (noAi?.block_rate_pct ?? 60)).toFixed(1)}%
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-slate-700 bg-black/35 p-3">
                  <div className="text-[11px] text-slate-400">WAF / Code tĩnh đã chặn</div>
                  <div className="mt-1 font-mono text-xl font-extrabold text-sky-300">
                    {(noAi?.attacks_blocked ?? 0).toLocaleString("vi-VN")}{" "}
                    <span className="text-xs font-normal text-slate-400">lượt</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    Chặn flood, IP xấu, token sai, payload lỗi
                  </div>
                </div>
                <div className="rounded-xl border border-rose-500/35 bg-black/35 p-3">
                  <div className="text-[11px] text-slate-400">Tấn công logic vượt qua WAF</div>
                  <div className="mt-1 font-mono text-xl font-extrabold text-rose-400">
                    {(noAi?.attacks_succeeded ?? 0).toLocaleString("vi-VN")}{" "}
                    <span className="text-xs font-normal text-slate-400">lọt qua</span>
                  </div>
                  <div className="text-[10px] text-rose-300/80 mt-0.5">
                    Thiệt hại: {formatVnd(noAi?.financial_loss_vnd ?? 0)} ({noAi?.compromised_accounts ?? 0} ví)
                  </div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-black/25 p-3">
                  <div className="text-[11px] text-slate-400">Khách thật bị WAF chặn nhầm</div>
                  <div className="mt-1 font-mono text-base font-bold text-orange-300">
                    {(noAi?.false_positives ?? 0).toLocaleString("vi-VN")}{" "}
                    <span className="text-[11px] text-orange-400">
                      ({noAi?.false_positive_rate_pct ?? 0.7}%)
                    </span>
                  </div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-black/25 p-3">
                  <div className="text-[11px] text-slate-400">Thời gian vá lỗ hổng (MTTR)</div>
                  <div className="mt-1 font-mono text-base font-bold text-amber-300">
                    ~{Math.round((noAi?.mttr_minutes ?? 180) / 60 * 10) / 10} giờ{" "}
                    <span className="text-[11px] font-normal text-slate-400">(thủ công)</span>
                  </div>
                </div>
              </div>

              {noAi?.traditional_layers && noAi.traditional_layers.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    5 lớp phòng thủ truyền thống đã chặn ({(noAi.attacks_blocked ?? 0).toLocaleString("vi-VN")} lượt)
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {noAi.traditional_layers.map((item) => (
                      <span
                        key={item.layer}
                        className="rounded-md border border-slate-700 bg-slate-900/90 px-2 py-1 text-[10px] text-slate-300"
                      >
                        {item.layer}:{" "}
                        <strong className="font-mono text-sky-300">
                          {item.blocked.toLocaleString("vi-VN")}
                        </strong>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="rounded-lg border border-rose-500/25 bg-black/30 px-3 py-2 text-[11px] text-slate-300">
                <strong className="text-rose-300">Khoảng trống ~20–35% còn lại (Last-Mile Gap):</strong>{" "}
                Các lớp tĩnh khó bắt kịp lỗi logic vừa deploy (sót <code>owner_id</code>, khe hở TOCTOU &lt;100ms, key bị lộ gọi từ IP sạch) và mất 1.5–3.5 giờ để đội SOC/Dev điều tra &amp; vá thủ công.
              </div>
            </div>

            {/* RIGHT: TRADITIONAL + FINSEC AI */}
            <div className="rounded-2xl border border-emerald-500/40 bg-gradient-to-br from-emerald-950/35 via-[#0d1424] to-[#0d1424] p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
                    <ShieldCheck className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-emerald-200">
                      BẢO MẬT TRUYỀN THỐNG + FINSEC AI{" "}
                      {showingProjected ? "(Xem trước Lá chắn AI)" : "(Đang chạy Live)"}
                    </h3>
                    <p className="text-[11px] text-emerald-300/75">
                      {showingProjected
                        ? "Bấm 'Bật Lá chắn AI' ở trên để áp dụng thật trên Live Middleware"
                        : `Đang bật ${scaleResult.active_rules_count} luật Virtual Patch bổ sung trên nền bảo mật sẵn có`}
                    </p>
                  </div>
                </div>
                <span className="rounded-full bg-emerald-500/20 border border-emerald-500/40 px-2.5 py-0.5 text-[11px] font-bold text-emerald-200 whitespace-nowrap">
                  {aiDisplay?.block_rate_pct ?? 100}% CHẶN (+{aiDisplay?.ai_gap_closed_pct ?? 0}% TỪ AI)
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-emerald-500/30 bg-black/35 p-3">
                  <div className="text-[11px] text-slate-400">Thiệt hại ngăn chặn thêm nhờ AI</div>
                  <div className="mt-1 font-mono text-xl font-extrabold text-emerald-400">
                    +{formatVnd(aiDisplay?.financial_saved_vnd ?? 0)}
                  </div>
                  <div className="text-[10px] text-emerald-300/80 mt-0.5">
                    Bịt kín phần lỗ hổng logic mà WAF tĩnh bỏ lọt
                  </div>
                </div>
                <div className="rounded-xl border border-emerald-500/30 bg-black/35 p-3">
                  <div className="text-[11px] text-slate-400">AI chặn bổ sung (vượt qua WAF)</div>
                  <div className="mt-1 font-mono text-xl font-extrabold text-sky-300">
                    +{(aiDisplay?.ai_extra_blocked ?? 0).toLocaleString("vi-VN")}{" "}
                    <span className="text-xs font-normal text-slate-400">lượt logic</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    Tổng chặn: {(aiDisplay?.attacks_blocked ?? 0).toLocaleString("vi-VN")} (HTTP 403 / 429)
                  </div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-black/25 p-3">
                  <div className="text-[11px] text-slate-400">Khách thật bị chặn nhầm (Dry-Run)</div>
                  <div className="mt-1 font-mono text-base font-bold text-emerald-300">
                    0 <span className="text-[11px] text-emerald-400">(0.00% · cứu {(noAi?.false_positives ?? 0).toLocaleString("vi-VN")} khách)</span>
                  </div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-black/25 p-3">
                  <div className="text-[11px] text-slate-400">Thời gian vá nóng (MTTR) &amp; Độ trễ</div>
                  <div className="mt-1 font-mono text-base font-bold text-sky-300">
                    &lt; 1 phút{" "}
                    <span className="text-[11px] font-normal text-slate-400">
                      ({aiDisplay?.avg_middleware_latency_ms ?? 1.8} ms)
                    </span>
                  </div>
                </div>
              </div>

              {/* 2-Layer AI Defense Explanation (aligns comparison with 2-layer architecture) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-[11px]">
                <div className="rounded-lg border border-emerald-500/25 bg-black/30 px-3 py-2">
                  <div className="font-bold text-emerald-300">Lớp 1 · Virtual Patching Middleware</div>
                  <div className="text-slate-400 mt-0.5">
                    Chặn tấn công ngay ở tầng biên (&lt;5ms) bằng luật khai báo JSON trước khi chạm vào Payment API.
                  </div>
                </div>
                <div className="rounded-lg border border-sky-500/25 bg-black/30 px-3 py-2">
                  <div className="font-bold text-sky-300">Lớp 2 · AI SOC &amp; Chống Prompt Injection</div>
                  <div className="text-slate-400 mt-0.5">
                    {aiDisplay?.prompt_injection_status && aiDisplay.prompt_injection_status !== "N/A"
                      ? aiDisplay.prompt_injection_status
                      : "Tự động điều tra ReAct, kiểm định Dry-Run 0% chặn nhầm và sinh Hotfix Diff."}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* PER-ACCOUNT IMPACT TABLE (CRYSTAL CLEAR ACCOUNT-BY-ACCOUNT COMPARISON) */}
          <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <WalletIcon className="h-4 w-4 text-sky-400" />
                  So sánh Tác động trên 5 Nhóm Tài khoản Đại diện của Hệ thống Fintech
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  5 tài khoản mô phỏng 5 phân khúc thực tế (Khách VIP, Khách phổ thông, Merchant, Đại lý Chi hộ, Quỹ Đối soát) — mỗi nhóm chịu mức độ tấn công khác nhau theo đúng hành vi thực tế.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#070b14]">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/95 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-3.5 py-2.5">Tài khoản &amp; Vai trò Hệ thống</th>
                    <th className="px-3.5 py-2.5">Số dư Gốc</th>
                    <th className="px-3.5 py-2.5 text-rose-300">Không có AI (Thiệt hại)</th>
                    <th className="px-3.5 py-2.5 text-emerald-300">
                      Có FinSec AI ({showingProjected ? "Xem trước Lá chắn AI" : "Đang bảo vệ Live"})
                    </th>
                    <th className="px-3.5 py-2.5">Mũi tấn công nhắm vào</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {scaleResult.accounts_comparison.map((acc) => {
                    const badge =
                      ACCOUNT_STATUS_BADGE[acc.without_ai_status] ||
                      ACCOUNT_STATUS_BADGE.SAFE;
                    const aiProtected = showingProjected
                      ? true
                      : acc.with_ai_live_status === "PROTECTED";
                    const aiBalance = showingProjected
                      ? acc.with_ai_full_balance
                      : acc.with_ai_live_balance;
                    const aiBlocked = showingProjected
                      ? acc.with_ai_full_blocked
                      : acc.with_ai_live_blocked;

                    return (
                      <tr key={acc.wallet_id} className="hover:bg-slate-900/40">
                        <td className="px-3.5 py-3 max-w-[260px]">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono font-bold text-white">{acc.wallet_id}</span>
                            <span className="font-mono text-[11px] text-slate-400">({acc.owner_id})</span>
                          </div>
                          {acc.role_label && (
                            <div className="text-[11px] font-semibold text-sky-300 mt-0.5">
                              {acc.role_label}
                            </div>
                          )}
                          {acc.role_note && (
                            <div className="text-[10px] text-slate-500 mt-0.5 leading-snug">
                              {acc.role_note}
                            </div>
                          )}
                        </td>
                        <td className="px-3.5 py-3 font-mono text-slate-300">
                          {formatVnd(acc.baseline_balance)}
                        </td>
                        <td className="px-3.5 py-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`font-mono font-bold ${
                                acc.without_ai_delta !== 0
                                  ? "text-rose-300"
                                  : "text-slate-300"
                              }`}
                            >
                              {formatVnd(acc.without_ai_balance)}
                            </span>
                            <span
                              className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${badge.cls}`}
                            >
                              {badge.label}
                            </span>
                          </div>
                          {acc.without_ai_delta !== 0 && (
                            <div className="text-[11px] font-mono text-rose-400 mt-0.5">
                              Biến động bất thường:{" "}
                              {acc.without_ai_delta > 0 ? "+" : ""}
                              {formatVnd(acc.without_ai_delta)}
                            </div>
                          )}
                          {acc.without_ai_records_leaked > 0 && (
                            <div className="text-[11px] text-orange-300 mt-0.5">
                              Rò rỉ {acc.without_ai_records_leaked.toLocaleString("vi-VN")} bản ghi sao kê
                            </div>
                          )}
                        </td>
                        <td className="px-3.5 py-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono font-bold text-emerald-300">
                              {formatVnd(aiBalance)}
                            </span>
                            {aiProtected ? (
                              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-bold text-emerald-300">
                                <CheckCircle2 className="h-3 w-3" />
                                AN TOÀN TUYỆT ĐỐI
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[10px] font-bold text-amber-300">
                                <AlertTriangle className="h-3 w-3" />
                                THIẾU LUẬT BẢO VỆ
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            Đã chặn{" "}
                            <span className="font-mono text-sky-300 font-semibold">
                              {aiBlocked.toLocaleString("vi-VN")}
                            </span>{" "}
                            request tấn công vào ví này
                          </div>
                        </td>
                        <td className="px-3.5 py-3">
                          <div className="flex flex-wrap gap-1">
                            {acc.targeted_vectors.length === 0 ? (
                              <span className="text-slate-500">—</span>
                            ) : (
                              acc.targeted_vectors.map((v) => (
                                <span
                                  key={v}
                                  className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-300"
                                >
                                  {v}
                                </span>
                              ))
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* MULTI-VECTOR BREAKDOWN (3-SEGMENT REAL SOC TELEMETRY) */}
          <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-bold text-white">
                Phân rã từng Mũi tấn công Đồng thời: WAF tĩnh chặn vs FinSec AI chặn bổ sung ({scaleResult.vector_breakdown.length} vectors)
              </h3>
              <div className="flex items-center gap-3 text-[10px] text-slate-400">
                <span className="inline-flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-sky-500" /> WAF/Code tĩnh đã chặn
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" /> FinSec AI chặn bổ sung
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-rose-500" /> Lọt qua (nếu chưa bật AI)
                </span>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scaleResult.vector_breakdown.map((v) => {
                const tradBlocked = v.blocked_by_traditional ?? 0;
                const aiExtra = showingProjected
                  ? (v.blocked_by_ai_extra_full ?? v.succeeded_without_ai)
                  : (v.blocked_by_ai_extra_live ?? 0);
                const tradPct = v.attempts > 0 ? Math.round((tradBlocked / v.attempts) * 100) : 0;
                const aiExtraPct = v.attempts > 0 ? Math.round((aiExtra / v.attempts) * 100) : 0;
                const leakedPct = Math.max(0, 100 - tradPct - aiExtraPct);

                return (
                  <div
                    key={v.vector}
                    className="rounded-xl border border-slate-800 bg-[#070b14] p-3.5 space-y-2"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-xs font-bold text-white">{v.label}</div>
                        <div className="text-[11px] font-mono text-slate-400">
                          {v.owasp} · {v.endpoint} · Rule: {v.condition_type}
                        </div>
                      </div>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-bold border whitespace-nowrap ${
                          v.rule_currently_active
                            ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                            : "bg-amber-500/15 text-amber-300 border-amber-500/40"
                        }`}
                      >
                        {v.rule_currently_active ? "LIVE ACTIVE" : "CHƯA ENFORCE"}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] font-mono">
                      <span className="text-sky-300">
                        WAF tĩnh: <strong>{tradBlocked.toLocaleString("vi-VN")} ({tradPct}%)</strong>
                      </span>
                      <span className="text-emerald-300">
                        AI chặn thêm: <strong>+{aiExtra.toLocaleString("vi-VN")} ({aiExtraPct}%)</strong>
                      </span>
                      <span className="text-rose-300">
                        Thiệt hại nếu lọt: <strong>{formatVnd(v.loss_without_ai_vnd)}</strong>
                      </span>
                    </div>

                    {/* 3-segment stacked bar: Traditional WAF + FinSec AI + Remaining Leaked */}
                    <div className="h-2.5 w-full rounded-full bg-slate-800 overflow-hidden flex">
                      <div
                        className="h-full bg-sky-500/80 transition-all"
                        style={{ width: `${tradPct}%` }}
                        title={`WAF tĩnh đã chặn: ${tradPct}%`}
                      />
                      <div
                        className="h-full bg-emerald-400 transition-all"
                        style={{ width: `${aiExtraPct}%` }}
                        title={`FinSec AI chặn bổ sung: ${aiExtraPct}%`}
                      />
                      {leakedPct > 0 && (
                        <div
                          className="h-full bg-rose-500/85 transition-all"
                          style={{ width: `${leakedPct}%` }}
                          title={`Đang lọt qua: ${leakedPct}%`}
                        />
                      )}
                    </div>

                    {v.traditional_gap_reason && (
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        {v.traditional_gap_reason}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
