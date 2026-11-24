"use client";

import React from "react";
import { Activity } from "lucide-react";
import { ApiLog } from "@/lib/api";

interface LiveLogsPanelProps {
  logs: ApiLog[];
}

export function LiveLogsPanel({ logs }: LiveLogsPanelProps) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-2.5">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Activity className="h-3.5 w-3.5 text-sky-400" />
          Live Sandbox HTTP Logs (Mới nhất từ DB)
        </h3>
        <span className="text-[11px] text-slate-500">
          {logs.length} live events
        </span>
      </div>
      <div className="max-h-56 overflow-y-auto rounded-xl border border-slate-800 bg-[#070b14]">
        {!logs.length ? (
          <div className="p-4 text-center text-xs text-slate-500">
            Chưa có log live (300 dòng clean baseline vẫn được giữ sẵn cho Dry-Run).
          </div>
        ) : (
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="sticky top-0 bg-slate-900/95 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-2.5 py-1.5">HTTP</th>
                <th className="px-2.5 py-1.5">Endpoint</th>
                <th className="px-2.5 py-1.5">IP</th>
                <th className="px-2.5 py-1.5">Actor / Key</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {logs.slice(0, 15).map((log) => (
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
  );
}
