"use client";

import React, { useState } from "react";
import {
  Briefcase,
  CheckSquare,
  Download,
  FileCode2,
  FileText,
  Lightbulb,
  Printer,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import { fetchIncidentExport, IncidentReport } from "@/lib/api";

interface IncidentAnalysisReportProps {
  incident: IncidentReport | null;
  onNotify?: (msg: string) => void;
  onError?: (msg: string) => void;
}

export function IncidentAnalysisReport({
  incident,
  onNotify,
  onError,
}: IncidentAnalysisReportProps) {
  const [exporting, setExporting] = useState<string | null>(null);

  if (!incident) {
    return (
      <div className="rounded-xl border border-dashed border-slate-700 bg-[#070b14] p-6 text-center text-xs text-slate-400">
        Chưa có sự cố nào được điều tra. Hãy kích hoạt một kịch bản tấn công và bấm{" "}
        <strong className="text-sky-300">AI SOC Điều tra</strong> để tạo bản phân tích
        chuyên sâu &amp; xuất báo cáo.
      </div>
    );
  }

  const analysis = incident.structured_analysis;
  const execSum = analysis?.executive_summary;
  const tech = analysis?.technical_analysis;

  const handleExport = async (format: "markdown" | "html" | "json") => {
    setExporting(format);
    try {
      const { content, filename, mimeType } = await fetchIncidentExport(
        incident.id,
        format
      );
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);

      if (format === "html") {
        const win = window.open(url, "_blank", "noopener,noreferrer");
        if (!win) {
          const a = document.createElement("a");
          a.href = url;
          a.download = filename;
          a.click();
        }
        onNotify?.("Đã mở bản báo cáo SOC chuẩn A4 — bạn có thể bấm In / Lưu thành PDF.");
      } else {
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        onNotify?.(`Đã tải xuống báo cáo ${filename}`);
      }
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) {
      onError?.(err instanceof Error ? err.message : "Xuất báo cáo thất bại");
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Export Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800 bg-[#070b14] p-3">
        <div>
          <div className="text-xs font-bold text-slate-200">
            Xuất Báo cáo Sự cố SOC ({incident.id})
          </div>
          <div className="text-[11px] text-slate-400">
            Gồm 2 lớp: Tóm tắt Điều hành (dễ hiểu) &amp; Phân tích Chuyên sâu (OWASP / CWE / MITRE / Hotfix)
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => handleExport("html")}
            disabled={exporting !== null}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500/20 border border-sky-500/40 px-2.5 py-1.5 text-[11px] font-semibold text-sky-200 hover:bg-sky-500/30 disabled:opacity-50 transition"
          >
            <Printer className="h-3.5 w-3.5" />
            {exporting === "html" ? "Đang tạo..." : "In / Lưu PDF"}
          </button>
          <button
            onClick={() => handleExport("markdown")}
            disabled={exporting !== null}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-[11px] font-semibold text-slate-200 hover:bg-slate-700 disabled:opacity-50 transition"
          >
            <FileText className="h-3.5 w-3.5" />
            {exporting === "markdown" ? "Đang tải..." : "Tải .MD"}
          </button>
          <button
            onClick={() => handleExport("json")}
            disabled={exporting !== null}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-[11px] font-semibold text-slate-200 hover:bg-slate-700 disabled:opacity-50 transition"
          >
            <FileCode2 className="h-3.5 w-3.5" />
            {exporting === "json" ? "Đang tải..." : "SIEM .JSON"}
          </button>
        </div>
      </div>

      {!execSum || !tech ? (
        <div className="rounded-xl border border-slate-800 bg-[#070b14] p-4 text-xs text-slate-400">
          Nhấn các nút xuất báo cáo phía trên để tải đầy đủ bản phân tích điều hành &amp; kỹ thuật từ backend.
        </div>
      ) : (
        <>
          {/* Layer 1: Executive Summary (Easy to understand) */}
          <div className="rounded-xl border border-sky-500/30 bg-sky-950/15 p-3.5 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-sky-300">
              <Briefcase className="h-3.5 w-3.5" />
              Phần 1 — Tóm tắt Điều hành (Dễ hiểu cho Lãnh đạo &amp; Vận hành)
            </div>

            <p className="text-xs text-slate-200 leading-relaxed">
              <strong className="text-white">Diễn biến: </strong>
              {execSum.what_happened}
            </p>

            <div className="flex items-start gap-2 rounded-lg border border-sky-500/30 bg-sky-950/40 p-2.5 text-xs text-sky-100">
              <Lightbulb className="h-4 w-4 text-amber-300 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-amber-200">Hình dung đời thực: </span>
                {execSum.plain_language_analogy}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <div className="rounded-lg border border-slate-800 bg-[#070b14]/80 p-2.5">
                <div className="text-[11px] font-semibold text-rose-300 mb-1">
                  Tác động Tài chính &amp; Kinh doanh
                </div>
                <p className="text-slate-300 leading-relaxed">{execSum.business_impact}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-[#070b14]/80 p-2.5">
                <div className="text-[11px] font-semibold text-emerald-300 mb-1">
                  Tình trạng Bảo vệ &amp; Blast Radius
                </div>
                <p className="text-slate-300 leading-relaxed">{execSum.protection_status}</p>
              </div>
            </div>
          </div>

          {/* Layer 2: Technical Deep-Dive (SOC / AppSec) */}
          <div className="rounded-xl border border-slate-800 bg-[#070b14] p-3.5 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-violet-300">
                <ShieldAlert className="h-3.5 w-3.5" />
                Phần 2 — Phân tích Kỹ thuật Chuyên sâu (SOC / AppSec)
              </div>
              <span className="rounded-md bg-slate-900 border border-slate-700 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                Engine: {tech.engine_used}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2">
                <div className="text-slate-400">OWASP API Top 10 (2023)</div>
                <div className="font-mono text-sky-300 mt-0.5">{tech.owasp_api_top_10}</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2">
                <div className="text-slate-400">Ước lượng CVSS v3.1</div>
                <div className="font-mono text-rose-300 mt-0.5">{tech.cvss_v31_estimate}</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2">
                <div className="text-slate-400">Phân loại CWE</div>
                <div className="text-slate-200 mt-0.5">{tech.cwe_mapping}</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2">
                <div className="text-slate-400">MITRE ATT&amp;CK</div>
                <div className="text-slate-200 mt-0.5">{tech.mitre_attack}</div>
              </div>
            </div>

            <div className="space-y-2 text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-semibold text-amber-300 flex items-center gap-1.5 mb-1">
                  <Wrench className="h-3.5 w-3.5" />
                  Nguyên nhân Gốc rễ (Root Cause)
                </div>
                <p className="text-slate-300 leading-relaxed">{tech.root_cause_analysis}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-semibold text-emerald-300 flex items-center gap-1.5 mb-1">
                  <Download className="h-3.5 w-3.5" />
                  Cơ chế Vá nóng Khai báo (Virtual Patching &lt;5ms)
                </div>
                <p className="text-slate-300 leading-relaxed">{tech.virtual_patch_mechanism}</p>
              </div>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5 mb-1.5">
                <CheckSquare className="h-3.5 w-3.5 text-emerald-400" />
                Kế hoạch Khắc phục &amp; Kiểm thử Hồi quy (Remediation Checklist)
              </div>
              <ol className="list-decimal pl-5 space-y-1 text-xs text-slate-300">
                {tech.remediation_checklist.map((item, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {item}
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
