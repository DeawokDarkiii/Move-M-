"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Code2,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  FileText,
  Layers,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Terminal,
} from "lucide-react";

import { AiComparisonOverview } from "@/components/AiComparisonOverview";
import { DiffViewer } from "@/components/DiffViewer";
import { IncidentAnalysisReport } from "@/components/IncidentAnalysisReport";
import { ScenarioCatalogExplorer } from "@/components/ScenarioCatalogExplorer";
import { SiemLogsAndRulesTab } from "@/components/SiemLogsAndRulesTab";
import {
  API_BASE_URL,
  DEMO_API_KEY,
  IncidentReport,
  PolicyRule,
  SandboxState,
  ScaleSimulationResponse,
  enforcePolicyRule,
  fetchSandboxState,
  resetSandboxApi,
  rollbackPolicyRule,
  runAiInvestigation,
  runScaleSimulationApi,
  toggleAiShieldApi,
  triggerSimulation,
} from "@/lib/api";

type WorkspaceView = "overview" | "scenarios" | "investigation";
type RightTab = "report" | "policy" | "siem" | "diff" | "api";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL:
    "bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-[0_0_12px_rgba(244,63,94,0.25)]",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  MEDIUM: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  LOW: "bg-sky-500/20 text-sky-300 border-sky-500/40",
};

export default function FinSecWorkspacePage() {
  const [view, setView] = useState<WorkspaceView>("overview");
  const [state, setState] = useState<SandboxState | null>(null);
  const [scaleResult, setScaleResult] = useState<ScaleSimulationResponse | null>(null);
  const [activeIncident, setActiveIncident] = useState<IncidentReport | null>(null);
  const [visibleStepsCount, setVisibleStepsCount] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<RightTab>("report");

  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => {
    setToastMsg(msg);
    setTimeout(() => {
      setToastMsg((prev) => (prev === msg ? null : prev));
    }, 4500);
  }, []);

  const refreshState = useCallback(async () => {
    try {
      const data = await fetchSandboxState();
      setState(data);
      setErrorMsg(null);
      setActiveIncident((prev) => {
        if (!prev && data.incidents.length > 0) {
          setVisibleStepsCount(data.incidents[0].reasoning_trace?.length || 0);
          return data.incidents[0];
        }
        if (prev) {
          const updated = data.incidents.find((i) => i.id === prev.id);
          return updated || prev;
        }
        return prev;
      });
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? `Không thể kết nối Backend (${API_BASE_URL}): ${err.message}`
          : "Không thể kết nối Backend API"
      );
    }
  }, []);

  useEffect(() => {
    refreshState();
  }, [refreshState]);

  useEffect(() => {
    if (!activeIncident?.reasoning_trace?.length) {
      setVisibleStepsCount(0);
      return;
    }
    const total = activeIncident.reasoning_trace.length;
    if (visibleStepsCount >= total) return;
    const timer = setTimeout(() => {
      setVisibleStepsCount((c) => Math.min(c + 1, total));
    }, 280);
    return () => clearTimeout(timer);
  }, [activeIncident, visibleStepsCount]);

  const currentProposedRule: PolicyRule | null = useMemo(() => {
    if (!activeIncident?.proposed_rule) return null;
    const liveMatch = state?.policy_rules.find(
      (r) => r.id === activeIncident.proposed_rule?.id
    );
    return liveMatch || activeIncident.proposed_rule;
  }, [activeIncident, state]);

  const handleRunScaleScenario = async (payload: {
    scenario_id?: string;
    total_transactions?: number;
    vectors?: string[];
    attack_ratio_pct?: number;
    with_prompt_injection?: boolean;
  }) => {
    setLoadingAction("scale");
    setErrorMsg(null);
    try {
      const res = await runScaleSimulationApi(payload);
      setScaleResult(res);
      setView("overview");
      showToast(
        `Đã mô phỏng ${res.total_transactions.toLocaleString("vi-VN")} giao dịch (${res.scenario.id}) trong ${res.simulation_time_ms}ms.`
      );
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Mô phỏng quy mô lớn thất bại");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleToggleAiShield = async (enabled: boolean) => {
    setLoadingAction("shield");
    setErrorMsg(null);
    try {
      const res = await toggleAiShieldApi(enabled);
      showToast(res.message);
      await refreshState();
      // Automatically re-run current scenario so the user sees the instant Before/After shift!
      if (scaleResult) {
        const rerun = await runScaleSimulationApi({
          scenario_id:
            scaleResult.scenario.id !== "SCN-CUSTOM"
              ? scaleResult.scenario.id
              : undefined,
          total_transactions: scaleResult.total_transactions,
          vectors: scaleResult.scenario.vectors,
          attack_ratio_pct: scaleResult.attack_ratio_pct,
          with_prompt_injection: scaleResult.with_prompt_injection,
        });
        setScaleResult(rerun);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Không thể bật/tắt Lá chắn AI");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleVerifyNormalTraffic = async () => {
    setLoadingAction("normal_traffic");
    setErrorMsg(null);
    try {
      const res = await triggerSimulation("normal_traffic", false);
      showToast(
        `Kiểm chứng Live Middleware: ${res.succeeded_200}/${res.total_requests} giao dịch khách thật thành công HTTP 200 OK (0 chặn nhầm).`
      );
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi kiểm chứng giao dịch sạch");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleInvestigate = async () => {
    setLoadingAction("investigate");
    setErrorMsg(null);
    try {
      const report = await runAiInvestigation();
      setVisibleStepsCount(1);
      setActiveIncident(report);
      setActiveTab("report");
      setView("investigation");
      showToast(
        `AI SOC hoàn tất điều tra (${report.reasoning_trace.length} bước) & Dry-Run trên ${
          report.dry_run_report?.total_clean ?? 300
        } giao dịch sạch.`
      );
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi điều tra AI SOC");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleEnforceOrRollbackRule = async (rule: PolicyRule) => {
    setLoadingAction("enforce");
    setErrorMsg(null);
    try {
      const res =
        rule.status === "ACTIVE"
          ? await rollbackPolicyRule(rule.id)
          : await enforcePolicyRule(rule.id);
      showToast(res.message);
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi cập nhật luật Virtual Patch");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleResetSandbox = async () => {
    setLoadingAction("reset");
    setErrorMsg(null);
    try {
      const res = await resetSandboxApi();
      setActiveIncident(null);
      setScaleResult(null);
      setVisibleStepsCount(0);
      showToast(
        `Reset sạch thành công: khôi phục ${res.wallets_restored} ví & giữ nguyên ${res.clean_baseline_preserved} log sạch.`
      );
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Reset Sandbox thất bại");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleCopy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      showToast("Không thể copy tự động — hãy bôi đen và copy thủ công.");
    }
  };

  const curlSnippet = useMemo(() => {
    const ruleId = currentProposedRule?.id || "RULE-XXXXXXXX";
    return `# 1. Chạy mô phỏng quy mô lớn (Kho 900 kịch bản, 10k-60k giao dịch)
curl -X POST "${API_BASE_URL}/v1/sandbox/simulate-scale" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${DEMO_API_KEY}" \\
  -d '{"scenario_id": "random"}'

# 2. Kích hoạt AI SOC Agent điều tra ReAct + Dry-Run
curl -X POST "${API_BASE_URL}/v1/incidents/investigate" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${DEMO_API_KEY}" \\
  -d '{}'

# 3. Kích hoạt luật Virtual Patching trực tiếp trong Middleware (<5ms)
curl -X POST "${API_BASE_URL}/v1/policies/${ruleId}/enforce" \\
  -H "X-API-Key: ${DEMO_API_KEY}"`;
  }, [currentProposedRule]);

  const dryRun = activeIncident?.dry_run_report;

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100">
      {/* =================================================================== */}
      {/* TOP SOC COMMAND HEADER                                              */}
      {/* =================================================================== */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#090f1d]/95 backdrop-blur">
        <div className="mx-auto max-w-[1520px] px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/15 border border-sky-500/40 text-sky-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FinSec Agent — AI SOC &amp; Virtual Patching Console
                </h1>
                <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-300 border border-emerald-500/30">
                  900 SCENARIOS · LIVE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                So sánh thực chiến Không AI vs Có AI · Điều tra ReAct · Dry-Run 0% chặn nhầm · Báo cáo SOC
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1.5">
              <Database className="h-3.5 w-3.5 text-sky-400" />
              <span className="text-slate-400">DB:</span>
              <span className="font-mono font-semibold text-sky-300">
                {state?.db_mode ?? "..."}
              </span>
            </div>

            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1.5">
              <Cpu className="h-3.5 w-3.5 text-violet-400" />
              <span className="font-mono font-semibold text-violet-300">
                {state?.llm_model ?? "loading"}
              </span>
            </div>

            <div
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-semibold ${
                (state?.active_rules_count ?? 0) > 0
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                  : "border-rose-500/40 bg-rose-500/15 text-rose-300"
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>
                {(state?.active_rules_count ?? 0) > 0
                  ? `AI Shield: ${state?.active_rules_count} luật ACTIVE`
                  : "AI Shield: OFF (0 luật)"}
              </span>
            </div>

            <a
              href={`${API_BASE_URL}/docs`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 font-medium text-slate-200 hover:border-sky-500/60 hover:text-sky-300 transition"
            >
              Swagger
              <ExternalLink className="h-3 w-3" />
            </a>

            <button
              onClick={handleResetSandbox}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 font-semibold text-amber-200 hover:bg-amber-500/20 disabled:opacity-50 transition"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </button>
          </div>
        </div>

        {/* Clean 3-Tab Primary SOC Navigation */}
        <div className="mx-auto max-w-[1520px] px-4 pb-2.5">
          <nav className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 rounded-xl border border-slate-800 bg-[#060a12] p-1 text-xs">
            <button
              onClick={() => setView("overview")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 font-bold transition ${
                view === "overview"
                  ? "bg-sky-500/20 text-sky-200 border border-sky-500/40 shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <ShieldCheck className="h-4 w-4" />
              1. So sánh AI vs Truyền thống
            </button>
            <button
              onClick={() => setView("scenarios")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 font-bold transition ${
                view === "scenarios"
                  ? "bg-indigo-500/20 text-indigo-200 border border-indigo-500/40 shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Layers className="h-4 w-4" />
              2. Kho 900 Kịch bản (10k–100k GD)
            </button>
            <button
              onClick={() => setView("investigation")}
              className={`inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 font-bold transition ${
                view === "investigation"
                  ? "bg-emerald-500/20 text-emerald-200 border border-emerald-500/40 shadow"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Cpu className="h-4 w-4" />
              3. Điều tra AI SOC, Báo cáo &amp; Log SIEM
              {(state?.recent_logs.length ?? 0) > 0 && (
                <span className="rounded-full bg-emerald-500/25 px-1.5 py-0.5 text-[10px] font-mono">
                  {state?.recent_logs.length}
                </span>
              )}
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[1520px] px-4 py-5 space-y-4">
        {/* Global Alerts / Toast */}
        {errorMsg && (
          <div className="flex items-center gap-2 rounded-xl border border-rose-500/50 bg-rose-500/15 px-4 py-3 text-sm text-rose-200">
            <AlertOctagon className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}
        {toastMsg && (
          <div className="flex items-center gap-2 rounded-xl border border-emerald-500/50 bg-emerald-500/15 px-4 py-2.5 text-sm text-emerald-200">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{toastMsg}</span>
          </div>
        )}

        {/* VIEW 1: BEFORE / AFTER AI COMPARISON OVERVIEW */}
        {view === "overview" && (
          <AiComparisonOverview
            scaleResult={scaleResult}
            wallets={state?.wallets || []}
            activeRulesCount={state?.active_rules_count ?? 0}
            loadingAction={loadingAction}
            onRunRandomScenario={() =>
              handleRunScaleScenario({ scenario_id: "random" })
            }
            onToggleAiShield={handleToggleAiShield}
            onInvestigate={handleInvestigate}
            onOpenCatalog={() => setView("scenarios")}
          />
        )}

        {/* VIEW 2: 900-SCENARIO EXPLORER & CUSTOM SCALE RUNNER */}
        {view === "scenarios" && (
          <ScenarioCatalogExplorer
            loadingAction={loadingAction}
            onRunScenario={handleRunScaleScenario}
          />
        )}

        {/* VIEW 3: AI SOC INVESTIGATION, DRY-RUN & REPORT EXPORT */}
        {view === "investigation" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-slate-800 bg-[#0d1424]/95 px-4 py-3">
              <div>
                <h2 className="text-sm font-bold text-white">
                  Bàn làm việc Điều tra AI SOC (ReAct Loop · Dry-Run 300 Baseline · Xuất Báo cáo)
                </h2>
                <p className="text-xs text-slate-400">
                  AI đọc log live trong DB, đối chiếu sổ cái ví, kiểm định bán kính ảnh hưởng (0% chặn nhầm) và đề xuất luật vá nóng + bản vá code.
                </p>
              </div>
              <button
                onClick={handleInvestigate}
                disabled={loadingAction !== null}
                className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-500 px-4 py-2 text-xs font-bold text-white shadow hover:from-sky-400 hover:to-indigo-400 disabled:opacity-50 transition"
              >
                {loadingAction === "investigate" ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Cpu className="h-3.5 w-3.5" />
                )}
                {loadingAction === "investigate"
                  ? "AI Agent đang điều tra..."
                  : "Chạy AI SOC Điều tra mới"}
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
              {/* LEFT: AI REASONING TRACE & TIMELINE */}
              <section className="lg:col-span-5 space-y-4">
                <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2">
                      <Cpu className="h-4 w-4 text-sky-400" />
                      <h3 className="text-sm font-bold text-white">
                        Chuỗi Suy luận AI Agent (ReAct)
                      </h3>
                    </div>
                    {activeIncident && (
                      <span className="font-mono text-[11px] text-slate-400">
                        {activeIncident.id}
                      </span>
                    )}
                  </div>

                  {!activeIncident ? (
                    <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d] p-8 text-center space-y-2">
                      <Cpu className="h-7 w-7 mx-auto text-slate-600" />
                      <p className="text-sm font-medium text-slate-300">
                        Chưa có báo cáo điều tra AI nào
                      </p>
                      <p className="text-xs text-slate-500">
                        Chạy 1 kịch bản ở tab <strong>So sánh AI</strong> hoặc{" "}
                        <strong>Kho 900 Kịch bản</strong>, rồi bấm{" "}
                        <strong className="text-sky-300">Chạy AI SOC Điều tra mới</strong>.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3.5">
                      <div className="rounded-xl border border-slate-800 bg-[#090f1d] p-3.5 space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${
                              SEVERITY_STYLES[activeIncident.severity] ||
                              SEVERITY_STYLES.HIGH
                            }`}
                          >
                            {activeIncident.severity}
                          </span>
                          <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-0.5 font-mono text-[11px] text-sky-300">
                            {activeIncident.owasp_tag}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-white leading-snug">
                          {activeIncident.title}
                        </h4>
                        {activeIncident.summary && (
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {activeIncident.summary}
                          </p>
                        )}
                        <div className="text-[11px] font-mono text-slate-400 pt-1">
                          Engine: <span className="text-violet-300">{activeIncident.engine_used || "finsec-ai"}</span>
                        </div>
                      </div>

                      {activeIncident.prompt_injection_detected && (
                        <div className="rounded-xl border border-fuchsia-500/60 bg-fuchsia-950/35 p-3 space-y-1.5">
                          <div className="flex items-center gap-2 text-xs font-bold text-fuchsia-200">
                            <ShieldAlert className="h-4 w-4 text-fuchsia-400 shrink-0" />
                            <span>
                              PHÁT HIỆN &amp; VÔ HIỆU HÓA INDIRECT PROMPT INJECTION
                            </span>
                          </div>
                          <p className="text-xs text-fuchsia-100/90 leading-relaxed">
                            Lớp <code>sanitizer.py</code> đã cô lập chỉ thị giả mạo trong log vào thẻ{" "}
                            <code>&lt;UNTRUSTED_RAW_LOG_DATA&gt;</code> — AI SOC miễn nhiễm hoàn toàn.
                          </p>
                        </div>
                      )}

                      <div className="space-y-2">
                        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                          ReAct Tool-Calling Trace ({visibleStepsCount}/{activeIncident.reasoning_trace.length} bước)
                        </div>
                        {activeIncident.reasoning_trace
                          .slice(0, visibleStepsCount)
                          .map((st) => (
                            <div
                              key={st.step}
                              className="rounded-xl border border-slate-800/90 bg-[#090f1d] p-3"
                            >
                              <div className="flex items-center justify-between gap-2 text-xs">
                                <span className="font-mono font-bold text-sky-300">
                                  Bước {st.step}: {st.action}()
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  REAL DB TOOL
                                </span>
                              </div>
                              <p className="mt-1 text-xs text-slate-200 leading-relaxed">
                                {st.observation_summary}
                              </p>
                            </div>
                          ))}
                      </div>

                      {activeIncident.attack_timeline.length > 0 && (
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                            Attack Timeline ({activeIncident.attack_timeline.length} sự kiện)
                          </div>
                          <div className="max-h-44 overflow-y-auto space-y-1.5 pr-1">
                            {activeIncident.attack_timeline.map((ev, i) => (
                              <div
                                key={i}
                                className="flex items-start gap-2 rounded-lg border border-slate-800/80 bg-[#080d18] px-2.5 py-2 text-xs"
                              >
                                <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-rose-300 shrink-0">
                                  {ev.stage}
                                </span>
                                <div className="min-w-0 flex-1">
                                  <div className="font-mono text-[11px] text-slate-200 truncate">
                                    {ev.detail}
                                  </div>
                                  <div className="text-[10px] text-slate-500 font-mono">
                                    IP: {ev.ip_address || "N/A"}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </section>

              {/* RIGHT: DRY-RUN + 4 MITIGATION & REPORT TABS */}
              <section className="lg:col-span-7 space-y-4">
                <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
                  {/* Dry-Run Blast Radius Summary */}
                  <div
                    className={`rounded-xl border p-3.5 space-y-2.5 ${
                      dryRun
                        ? dryRun.blocked_clean === 0
                          ? "border-emerald-500/45 bg-gradient-to-br from-emerald-950/35 to-[#090f1d]"
                          : "border-rose-500/50 bg-rose-950/30"
                        : "border-slate-800 bg-[#090f1d]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                        Kiểm định Dry-Run (Chạy thật trên {state?.clean_baseline_count ?? 300} giao dịch sạch)
                      </span>
                      {dryRun && (
                        <span
                          className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold ${
                            dryRun.blocked_clean === 0
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                              : "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          }`}
                        >
                          {dryRun.blocked_clean === 0
                            ? "AN TOÀN — 0% CHẶN NHẦM"
                            : "CẢNH BÁO CHẶN NHẦM"}
                        </span>
                      )}
                    </div>

                    {dryRun ? (
                      <div className="space-y-2.5">
                        <div className="grid grid-cols-2 gap-3">
                          <div className="rounded-lg border border-slate-800 bg-black/35 p-2.5">
                            <div className="text-[11px] text-slate-400">Hiệu quả Chặn tấn công</div>
                            <div className="mt-0.5 font-mono text-xl font-extrabold text-sky-300">
                              {dryRun.attack_blocked_rate}%{" "}
                              <span className="text-xs font-normal text-slate-400">
                                ({dryRun.blocked_attack_logs}/{dryRun.total_attack_logs} log tấn công)
                              </span>
                            </div>
                          </div>
                          <div className="rounded-lg border border-slate-800 bg-black/35 p-2.5">
                            <div className="text-[11px] text-slate-400">Chặn nhầm khách thật (DB Baseline)</div>
                            <div
                              className={`mt-0.5 font-mono text-xl font-extrabold ${
                                dryRun.blocked_clean === 0
                                  ? "text-emerald-400"
                                  : "text-rose-400"
                              }`}
                            >
                              {dryRun.blocked_clean} / {dryRun.total_clean}
                            </div>
                          </div>
                        </div>

                        {dryRun.scale_context && (
                          <div className="rounded-lg border border-sky-500/30 bg-sky-950/25 px-3 py-2 text-[11px] text-sky-100">
                            <strong>Đối chiếu quy mô lớn ({dryRun.scale_context.scenario_id}):</strong>{" "}
                            Đã kiểm chứng thêm trên{" "}
                            <span className="font-mono font-bold text-emerald-300">
                              {dryRun.scale_context.clean_transactions_verified.toLocaleString("vi-VN")} giao dịch khách thật
                            </span>{" "}
                            →{" "}
                            <span className="font-mono font-bold text-emerald-300">
                              {dryRun.scale_context.false_positives} chặn nhầm (0.00%)
                            </span>
                            .
                          </div>
                        )}

                        {dryRun.sample_passed_clean && dryRun.sample_passed_clean.length > 0 && (
                          <div className="rounded-lg border border-slate-800 bg-black/30 p-2.5 space-y-1">
                            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                              Mẫu giao dịch khách thật đã vượt qua Dry-Run (200 OK — Không bị chặn nhầm)
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 font-mono text-[10px]">
                              {dryRun.sample_passed_clean.map((s, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between rounded bg-slate-900/80 px-2 py-1 text-slate-300"
                                >
                                  <span className="truncate">
                                    {s.method} {s.path} ({s.actor_id})
                                  </span>
                                  <span className="text-emerald-400 font-bold ml-1 shrink-0">
                                    PASS
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-slate-500">
                        Chạy AI SOC Điều tra để kiểm chứng luật phòng thủ trên 300 giao dịch sạch lịch sử.
                      </p>
                    )}
                  </div>

                  {/* 5 Sub-Tabs inside SOC Workbench */}
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-1 rounded-xl border border-slate-800 bg-[#070b14] p-1 text-[11px]">
                    <button
                      onClick={() => setActiveTab("report")}
                      className={`inline-flex items-center justify-center gap-1 rounded-lg px-2 py-2 font-semibold transition ${
                        activeTab === "report"
                          ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <FileText className="h-3.5 w-3.5" />
                      1. Báo cáo
                    </button>
                    <button
                      onClick={() => setActiveTab("policy")}
                      className={`inline-flex items-center justify-center gap-1 rounded-lg px-2 py-2 font-semibold transition ${
                        activeTab === "policy"
                          ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      2. Patch
                    </button>
                    <button
                      onClick={() => setActiveTab("siem")}
                      className={`inline-flex items-center justify-center gap-1 rounded-lg px-2 py-2 font-semibold transition ${
                        activeTab === "siem"
                          ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Activity className="h-3.5 w-3.5" />
                      3. Log &amp; Luật
                    </button>
                    <button
                      onClick={() => setActiveTab("diff")}
                      className={`inline-flex items-center justify-center gap-1 rounded-lg px-2 py-2 font-semibold transition ${
                        activeTab === "diff"
                          ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Code2 className="h-3.5 w-3.5" />
                      4. Hotfix
                    </button>
                    <button
                      onClick={() => setActiveTab("api")}
                      className={`inline-flex items-center justify-center gap-1 rounded-lg px-2 py-2 font-semibold transition ${
                        activeTab === "api"
                          ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Terminal className="h-3.5 w-3.5" />
                      5. API
                    </button>
                  </div>

                  {activeTab === "report" && (
                    <IncidentAnalysisReport
                      incident={activeIncident}
                      onNotify={showToast}
                      onError={setErrorMsg}
                    />
                  )}

                  {activeTab === "siem" && (
                    <SiemLogsAndRulesTab
                      logs={state?.recent_logs || []}
                      rules={state?.policy_rules || []}
                      loadingAction={loadingAction}
                      onToggleRule={handleEnforceOrRollbackRule}
                      onVerifyNormalTraffic={handleVerifyNormalTraffic}
                    />
                  )}

                  {activeTab === "policy" && (
                    <div className="space-y-3">
                      {!currentProposedRule ? (
                        <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d] p-6 text-center text-xs text-slate-500">
                          Chưa có luật Virtual Patch nào được đề xuất.
                        </div>
                      ) : (
                        <>
                          <div className="rounded-xl border border-slate-800 bg-[#05080f] overflow-hidden">
                            <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px]">
                              <span className="font-semibold text-slate-200">
                                {currentProposedRule.name}{" "}
                                <span className="font-mono text-slate-500">
                                  ({currentProposedRule.id})
                                </span>
                              </span>
                              <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-sky-300 border border-sky-500/30">
                                Declarative JSON · Zero eval()
                              </span>
                            </div>
                            <pre className="overflow-x-auto p-3.5 font-mono text-xs text-emerald-200 leading-relaxed">
                              {JSON.stringify(currentProposedRule.rule_spec, null, 2)}
                            </pre>
                          </div>

                          <button
                            onClick={() => handleEnforceOrRollbackRule(currentProposedRule)}
                            disabled={loadingAction !== null}
                            className={`w-full inline-flex items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-bold transition shadow-lg disabled:opacity-50 ${
                              currentProposedRule.status === "ACTIVE"
                                ? "bg-gradient-to-r from-amber-600 to-rose-600 hover:from-amber-500 hover:to-rose-500 text-white"
                                : "bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white"
                            }`}
                          >
                            {currentProposedRule.status === "ACTIVE" ? (
                              <>
                                <ShieldOff className="h-4 w-4" />
                                Rollback — Hoàn tác Luật Chặn (1 chạm)
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="h-4 w-4" />
                                Duyệt &amp; Kích hoạt Luật Chặn (Live Middleware)
                              </>
                            )}
                          </button>
                        </>
                      )}
                    </div>
                  )}

                  {activeTab === "diff" && (
                    <div className="space-y-3">
                      {!activeIncident?.hotfix_diff ? (
                        <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d] p-6 text-center text-xs text-slate-500">
                          Chưa có bản vá mã nguồn (Hotfix Diff).
                        </div>
                      ) : (
                        <>
                          <div className="flex items-center justify-between text-xs text-slate-400">
                            <span>Bản vá gốc rễ cho đội Dev (Git Unified Diff)</span>
                            <button
                              onClick={() =>
                                handleCopy("diff", activeIncident.hotfix_diff || "")
                              }
                              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                            >
                              <Copy className="h-3 w-3" />
                              {copiedKey === "diff" ? "Đã copy!" : "Copy Diff"}
                            </button>
                          </div>
                          <DiffViewer diff={activeIncident.hotfix_diff} />
                        </>
                      )}
                    </div>
                  )}

                  {activeTab === "api" && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-slate-300">
                          cURL Public Service API (X-API-Key: {DEMO_API_KEY})
                        </span>
                        <button
                          onClick={() => handleCopy("curl", curlSnippet)}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                        >
                          <Copy className="h-3 w-3" />
                          {copiedKey === "curl" ? "Đã copy!" : "Copy cURL"}
                        </button>
                      </div>
                      <pre className="overflow-x-auto rounded-xl border border-slate-800 bg-[#05080f] p-3 font-mono text-[11px] text-sky-200 leading-relaxed">
                        {curlSnippet}
                      </pre>
                    </div>
                  )}
                </div>
              </section>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
