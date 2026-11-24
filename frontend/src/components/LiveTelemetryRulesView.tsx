"use client";

import React, { useMemo, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Flame,
  KeyRound,
  Lock,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  UserCheck,
  Zap,
} from "lucide-react";
import {
  ApiLog,
  PolicyRule,
  SimulationResponse,
  Wallet,
} from "@/lib/api";
import { WalletMonitorGrid } from "@/components/WalletMonitorGrid";

interface LiveTelemetryRulesViewProps {
  logs: ApiLog[];
  rules: PolicyRule[];
  wallets: Wallet[];
  lastSim: SimulationResponse | null;
  loadingAction: string | null;
  onSimulateClassic: (
    scenario:
      | "webhook_replay"
      | "bola_idor"
      | "leaked_key"
      | "race_condition"
      | "prompt_injection"
      | "normal_traffic"
  ) => void;
  onToggleRule: (rule: PolicyRule) => void;
}

export function LiveTelemetryRulesView({
  logs,
  rules,
  wallets,
  lastSim,
  loadingAction,
  onSimulateClassic,
  onToggleRule,
}: LiveTelemetryRulesViewProps) {
  const [statusFilter, setStatusFilter] = useState<"all" | "ok" | "blocked">("all");
  const [logSearch, setLogSearch] = useState("");

  const filteredLogs = useMemo(() => {
    const q = logSearch.trim().toLowerCase();
    return logs.filter((log) => {
      if (statusFilter === "ok" && log.status_code >= 400) return false;
      if (statusFilter === "blocked" && log.status_code < 400) return false;
      if (q) {
        const hay = `${log.method} ${log.path} ${log.ip_address} ${log.actor_id || ""} ${log.api_key_id || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [logs, statusFilter, logSearch]);

  return (
    <div className="space-y-5">
      {/* Live Middleware Probe Strip + Wallets */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-sky-400" />
              Kiểm thử Trực tiếp Live Middleware (Real HTTP Requests)
            </h2>
            <p className="text-xs text-slate-400">
              Bắn request HTTP thật đi qua Middleware (&lt;5ms) để kiểm chứng tấn công bị chặn 403/429 trong khi khách thật vẫn nhận 200 OK.
            </p>
          </div>
          {lastSim && (
            <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 font-mono text-[11px] text-slate-200">
              Vừa gửi: <strong>{lastSim.scenario}</strong> ·{" "}
              <span className="text-emerald-300">{lastSim.succeeded_200} OK</span> ·{" "}
              <span className="text-rose-300">{lastSim.blocked_count} BLOCKED</span>
            </span>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSimulateClassic("webhook_replay")}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-500/20 disabled:opacity-50"
          >
            <Flame className="h-3.5 w-3.5 text-rose-400" />
            Webhook Replay
          </button>
          <button
            onClick={() => onSimulateClassic("bola_idor")}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-orange-500/40 bg-orange-500/10 px-3 py-1.5 text-xs font-semibold text-orange-200 hover:bg-orange-500/20 disabled:opacity-50"
          >
            <UserCheck className="h-3.5 w-3.5 text-orange-400" />
            BOLA / IDOR
          </button>
          <button
            onClick={() => onSimulateClassic("leaked_key")}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-500/20 disabled:opacity-50"
          >
            <KeyRound className="h-3.5 w-3.5 text-amber-400" />
            Lộ Internal Key
          </button>
          <button
            onClick={() => onSimulateClassic("race_condition")}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-pink-500/40 bg-pink-500/10 px-3 py-1.5 text-xs font-semibold text-pink-200 hover:bg-pink-500/20 disabled:opacity-50"
          >
            <Zap className="h-3.5 w-3.5 text-pink-400" />
            Race Condition
          </button>
          <button
            onClick={() => onSimulateClassic("prompt_injection")}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-fuchsia-500/40 bg-fuchsia-500/10 px-3 py-1.5 text-xs font-semibold text-fuchsia-200 hover:bg-fuchsia-500/20 disabled:opacity-50"
          >
            <ShieldAlert className="h-3.5 w-3.5 text-fuchsia-400" />
            Prompt Injection
          </button>
          <button
            onClick={() => onSimulateClassic("normal_traffic")}
            disabled={loadingAction !== null}
            className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 text-xs font-bold text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
          >
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            Gửi Giao dịch Khách thật (200 OK)
          </button>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 pt-1">
          <WalletMonitorGrid wallets={wallets} />
          <div className="xl:col-span-5 rounded-xl border border-slate-800 bg-[#090f1d] p-3 text-xs text-slate-400 flex items-center">
            {lastSim ? (
              <div className="w-full space-y-1">
                {lastSim.results.slice(0, 3).map((r) => (
                  <div key={r.seq} className="flex items-center justify-between font-mono text-[11px]">
                    <span className="truncate text-slate-300 max-w-[260px]">
                      {r.label || `${r.method} ${r.path}`}
                    </span>
                    <span
                      className={`rounded px-1.5 py-0.5 font-bold ${
                        r.blocked
                          ? "bg-rose-500/20 text-rose-300"
                          : "bg-emerald-500/20 text-emerald-300"
                      }`}
                    >
                      {r.status_code} {r.blocked ? "BLOCKED" : "OK"}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <span>Chọn 1 nút kiểm thử ở trên để xem phản hồi thực từ Live Middleware.</span>
            )}
          </div>
        </div>
      </div>

      {/* Policy Rules Management Table */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Lock className="h-4 w-4 text-emerald-400" />
            Quản lý Luật Virtual Patching ({rules.length} luật trong DB)
          </h3>
          <span className="text-xs text-slate-400">
            Bật / tắt độc lập từng luật trực tiếp trên Middleware (&lt;5ms)
          </span>
        </div>

        {rules.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 bg-[#070b14] p-5 text-center text-xs text-slate-500">
            Chưa có luật nào. Hãy bấm <strong>Bật Lá chắn AI</strong> ở trang Tổng quan hoặc chạy <strong>AI SOC Điều tra</strong>.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#070b14]">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/95 text-[11px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-3 py-2">Mã &amp; Tên Luật</th>
                  <th className="px-3 py-2">Loại Điều kiện</th>
                  <th className="px-3 py-2">Endpoint bảo vệ</th>
                  <th className="px-3 py-2">Trạng thái</th>
                  <th className="px-3 py-2 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {rules.map((r) => {
                  const isActive = r.status === "ACTIVE";
                  return (
                    <tr key={r.id} className="hover:bg-slate-900/40">
                      <td className="px-3 py-2.5">
                        <div className="font-semibold text-white">{r.name}</div>
                        <div className="font-mono text-[10px] text-slate-500">{r.id}</div>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-sky-300">
                        {r.rule_spec.condition_type}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate-300">
                        {r.rule_spec.target_path_prefix}
                      </td>
                      <td className="px-3 py-2.5">
                        <span
                          className={`rounded-full px-2 py-0.5 text-[10px] font-bold border ${
                            isActive
                              ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                              : r.status === "ROLLED_BACK"
                              ? "bg-amber-500/15 text-amber-300 border-amber-500/40"
                              : "bg-slate-800 text-slate-300 border-slate-700"
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button
                          onClick={() => onToggleRule(r)}
                          disabled={loadingAction !== null}
                          className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-bold border transition disabled:opacity-50 ${
                            isActive
                              ? "bg-rose-500/15 border-rose-500/40 text-rose-200 hover:bg-rose-500/25"
                              : "bg-emerald-500/15 border-emerald-500/40 text-emerald-200 hover:bg-emerald-500/25"
                          }`}
                        >
                          {isActive ? (
                            <>
                              <ShieldOff className="h-3 w-3" /> Rollback
                            </>
                          ) : (
                            <>
                              <ShieldCheck className="h-3 w-3" /> Enforce
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Filterable SIEM HTTP Logs Table */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-bold text-white">
            Nhật ký HTTP / SIEM Live ({filteredLogs.length} / {logs.length} sự kiện gần nhất)
          </h3>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
                placeholder="Lọc IP, endpoint, actor..."
                className="rounded-lg border border-slate-700 bg-[#070b14] pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>
            <div className="flex rounded-lg border border-slate-700 bg-[#070b14] p-0.5 text-[11px]">
              {(
                [
                  ["all", "Tất cả"],
                  ["blocked", "Bị chặn (403/429)"],
                  ["ok", "Thành công (200)"],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setStatusFilter(key)}
                  className={`rounded-md px-2.5 py-1 font-semibold transition ${
                    statusFilter === key
                      ? "bg-sky-500/20 text-sky-200"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="max-h-96 overflow-y-auto rounded-xl border border-slate-800 bg-[#070b14]">
          {filteredLogs.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              Không có log nào khớp bộ lọc hiện tại.
            </div>
          ) : (
            <table className="w-full text-left font-mono text-[11px]">
              <thead className="sticky top-0 bg-slate-900/95 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-3 py-2">HTTP</th>
                  <th className="px-3 py-2">Endpoint</th>
                  <th className="px-3 py-2">IP Nguồn</th>
                  <th className="px-3 py-2">Actor / Key</th>
                  <th className="px-3 py-2">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/50">
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span
                        className={`rounded px-1.5 py-0.5 font-bold ${
                          log.status_code >= 400
                            ? "bg-rose-500/20 text-rose-300"
                            : "bg-emerald-500/20 text-emerald-300"
                        }`}
                      >
                        {log.status_code}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-200">
                      {log.method} {log.path}
                    </td>
                    <td className="px-3 py-2 text-sky-300 whitespace-nowrap">
                      {log.ip_address}
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {log.api_key_id || log.actor_id || "-"}
                    </td>
                    <td className="px-3 py-2 text-slate-500 truncate max-w-[220px]">
                      {log.user_agent || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
