"use client";

import React, { useMemo, useState } from "react";
import {
  CheckCircle2,
  Lock,
  Search,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { ApiLog, PolicyRule } from "@/lib/api";

interface SiemLogsAndRulesTabProps {
  logs: ApiLog[];
  rules: PolicyRule[];
  loadingAction: string | null;
  onToggleRule: (rule: PolicyRule) => void;
  onVerifyNormalTraffic: () => void;
}

export function SiemLogsAndRulesTab({
  logs,
  rules,
  loadingAction,
  onToggleRule,
  onVerifyNormalTraffic,
}: SiemLogsAndRulesTabProps) {
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
    <div className="space-y-4">
      {/* Per-Rule Middleware Control Table */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5 text-emerald-400" />
            Quản lý từng Luật Virtual Patch ({rules.length} luật)
          </div>
          <button
            onClick={onVerifyNormalTraffic}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1 text-[11px] font-semibold text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50 transition"
          >
            <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            Kiểm chứng Khách thật (HTTP 200 OK)
          </button>
        </div>

        {rules.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 bg-[#070b14] p-4 text-center text-xs text-slate-500">
            Chưa có luật nào trong DB. Hãy bấm <strong>Bật Lá chắn AI</strong> ở Tab 1 hoặc chạy{" "}
            <strong>AI SOC Điều tra</strong>.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#070b14]">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-slate-900/95 text-[10px] uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-3 py-2">Tên Luật</th>
                  <th className="px-3 py-2">Điều kiện</th>
                  <th className="px-3 py-2">Trạng thái</th>
                  <th className="px-3 py-2 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {rules.map((r) => {
                  const isActive = r.status === "ACTIVE";
                  return (
                    <tr key={r.id} className="hover:bg-slate-900/40">
                      <td className="px-3 py-2">
                        <div className="font-semibold text-slate-200">{r.name}</div>
                        <div className="font-mono text-[10px] text-slate-500">
                          {r.rule_spec.target_path_prefix}
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-[10px] text-sky-300">
                        {r.rule_spec.condition_type}
                      </td>
                      <td className="px-3 py-2">
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
                      <td className="px-3 py-2 text-right">
                        <button
                          onClick={() => onToggleRule(r)}
                          disabled={loadingAction !== null}
                          className={`inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[10px] font-bold border transition disabled:opacity-50 ${
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

      {/* Searchable Raw SIEM HTTP Logs */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs font-bold text-slate-200">
            Nhật ký SIEM Gốc ({filteredLogs.length} / {logs.length} sự kiện)
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <div className="relative">
              <Search className="h-3 w-3 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
                placeholder="Lọc IP, endpoint, actor..."
                className="rounded-lg border border-slate-700 bg-[#070b14] pl-7 pr-2.5 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none w-44"
              />
            </div>
            <div className="flex rounded-lg border border-slate-700 bg-[#070b14] p-0.5 text-[10px]">
              {(
                [
                  ["all", "Tất cả"],
                  ["blocked", "Bị chặn"],
                  ["ok", "200 OK"],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setStatusFilter(key)}
                  className={`rounded px-2 py-1 font-semibold transition ${
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

        <div className="max-h-64 overflow-y-auto rounded-xl border border-slate-800 bg-[#070b14]">
          {filteredLogs.length === 0 ? (
            <div className="p-5 text-center text-xs text-slate-500">
              Chưa có log live khớp bộ lọc (chạy 1 kịch bản ở Tab 1 hoặc Tab 2 để ghi nhận log).
            </div>
          ) : (
            <table className="w-full text-left font-mono text-[11px]">
              <thead className="sticky top-0 bg-slate-900/95 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-2.5 py-1.5">HTTP</th>
                  <th className="px-2.5 py-1.5">Endpoint</th>
                  <th className="px-2.5 py-1.5">IP Nguồn</th>
                  <th className="px-2.5 py-1.5">Actor / Key</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/50">
                    <td className="px-2.5 py-1.5 whitespace-nowrap">
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
                    <td className="px-2.5 py-1.5 text-slate-200 truncate max-w-[200px]">
                      {log.method} {log.path}
                    </td>
                    <td className="px-2.5 py-1.5 text-sky-300 whitespace-nowrap">
                      {log.ip_address}
                    </td>
                    <td className="px-2.5 py-1.5 text-slate-400 truncate max-w-[130px]">
                      {log.api_key_id || log.actor_id || "-"}
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
