"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Code2,
  Copy,
  Cpu,
  Database,
  ExternalLink,
  Flame,
  KeyRound,
  Lock,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Terminal,
  UserCheck,
  Wallet as WalletIcon,
  Zap,
} from "lucide-react";

import { DiffViewer } from "@/components/DiffViewer";
import {
  API_BASE_URL,
  DEMO_API_KEY,
  IncidentReport,
  PolicyRule,
  SandboxState,
  SimulationResponse,
  enforcePolicyRule,
  fetchSandboxState,
  formatVnd,
  resetSandboxApi,
  rollbackPolicyRule,
  runAiInvestigation,
  triggerSimulation,
} from "@/lib/api";

type RightTab = "policy" | "diff" | "api";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL:
    "bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-[0_0_12px_rgba(244,63,94,0.25)]",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/50",
  MEDIUM: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  LOW: "bg-sky-500/20 text-sky-300 border-sky-500/40",
};

export default function FinSecWorkspacePage() {
  const [state, setState] = useState<SandboxState | null>(null);
  const [activeIncident, setActiveIncident] = useState<IncidentReport | null>(null);
  const [visibleStepsCount, setVisibleStepsCount] = useState<number>(0);
  const [lastSim, setLastSim] = useState<SimulationResponse | null>(null);
  const [withPromptInjection, setWithPromptInjection] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<RightTab>("policy");

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
          if (updated) {
            return {
              ...prev,
              ...updated,
              summary: prev.summary,
              prompt_injection_detected: prev.prompt_injection_detected,
              prompt_injection_evidence: prev.prompt_injection_evidence,
              engine_used: prev.engine_used,
            };
          }
        }
        return prev;
      });
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? `Không thể kết nối Backend (${API_BASE_URL}): ${err.message}`
          : "Không thể kết nối Backend"
      );
    }
  }, []);

  useEffect(() => {
    refreshState();
  }, [refreshState]);

  // Animate reasoning_trace steps sequentially whenever a new incident arrives
  useEffect(() => {
    if (!activeIncident?.reasoning_trace?.length) {
      setVisibleStepsCount(0);
      return;
    }
    const total = activeIncident.reasoning_trace.length;
    if (visibleStepsCount >= total) return;

    const timer = setTimeout(() => {
      setVisibleStepsCount((c) => Math.min(c + 1, total));
    }, 260);
    return () => clearTimeout(timer);
  }, [activeIncident, visibleStepsCount]);

  // Find current live status of proposed rule from state.policy_rules
  const currentProposedRule: PolicyRule | null = useMemo(() => {
    if (!activeIncident?.proposed_rule) return null;
    const liveMatch = state?.policy_rules.find(
      (r) => r.id === activeIncident.proposed_rule?.id
    );
    return liveMatch || activeIncident.proposed_rule;
  }, [activeIncident, state]);

  const handleSimulate = async (
    scenario:
      | "webhook_replay"
      | "bola_idor"
      | "leaked_key"
      | "race_condition"
      | "prompt_injection"
      | "normal_traffic",
    label: string
  ) => {
    setLoadingAction(`sim:${scenario}`);
    setErrorMsg(null);
    try {
      const inject = scenario === "prompt_injection" ? true : withPromptInjection;
      const res = await triggerSimulation(scenario, inject);
      setLastSim(res);
      await refreshState();

      if (scenario === "normal_traffic") {
        showToast(
          `Giao dịch khách hàng sạch: ${res.succeeded_200}/${res.total_requests} trả về 200 OK (0 bị chặn nhầm).`
        );
      } else if (res.blocked_count > 0 && res.succeeded_200 === 0) {
        showToast(
          `Virtual Patch ĐÃ CHẶN THÀNH CÔNG ${res.blocked_count}/${res.total_requests} request của "${label}" (HTTP 403/429)!`
        );
      } else {
        showToast(
          `Đã bắn "${label}": ${res.succeeded_200} request lọt qua (200 OK). Bấm "AI SOC Điều tra" để phân tích & vá ảo!`
        );
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi mô phỏng tấn công");
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
      setActiveTab("policy");
      await refreshState();
      showToast(
        `AI SOC hoàn tất điều tra (${report.reasoning_trace.length} bước) & Dry-Run trên ${
          report.dry_run_report?.total_clean ?? 300
        } log sạch!`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi AI SOC điều tra");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleEnforceOrRollback = async () => {
    if (!currentProposedRule) return;
    const isActive = currentProposedRule.status === "ACTIVE";
    setLoadingAction(isActive ? "rollback" : "enforce");
    setErrorMsg(null);
    try {
      if (isActive) {
        const res = await rollbackPolicyRule(currentProposedRule.id);
        showToast(res.message);
      } else {
        const res = await enforcePolicyRule(currentProposedRule.id);
        showToast(res.message);
      }
      await refreshState();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi cập nhật Policy Rule");
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
      setLastSim(null);
      setVisibleStepsCount(0);
      await refreshState();
      showToast(
        `Đã Reset Sandbox sạch sẽ: khôi phục ${res.wallets_restored} ví (10.000.000₫) & giữ nguyên ${res.clean_baseline_preserved} dòng clean baseline.`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Lỗi Reset Sandbox");
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
      // ignore clipboard errors in restricted frames
    }
  };

  const curlSnippet = useMemo(() => {
    const ruleId = currentProposedRule?.id || "RULE-XXXXXXXX";
    return `# 1. Đẩy log từ cổng thanh toán fintech vào FinSec Agent
curl -X POST "${API_BASE_URL}/v1/logs/ingest" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${DEMO_API_KEY}" \\
  -d '{"logs":[{"method":"POST","path":"/sandbox/webhook/payment-success","status_code":200,"ip_address":"45.133.1.99","user_agent":"ReplayBot","request_body":{"event_id":"evt_replay_99881","wallet_id":"W_1001","amount":5000000}}]}'

# 2. Kích hoạt AI SOC Agent điều tra & Dry-Run kiểm chứng 0 chặn nhầm
curl -X POST "${API_BASE_URL}/v1/incidents/investigate" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${DEMO_API_KEY}" \\
  -d '{}'

# 3. Kích hoạt Virtual Patch Rule trong Live Middleware (<5ms)
curl -X POST "${API_BASE_URL}/v1/policies/${ruleId}/enforce" \\
  -H "X-API-Key: ${DEMO_API_KEY}"

# 4. Rollback luật chặn 1 chạm (hoặc Reset toàn bộ Sandbox)
curl -X POST "${API_BASE_URL}/v1/policies/${ruleId}/rollback" \\
  -H "X-API-Key: ${DEMO_API_KEY}"`;
  }, [currentProposedRule]);

  const dryRun = activeIncident?.dry_run_report;

  return (
    <div className="min-h-screen soc-grid-bg text-slate-100 flex flex-col">
      {/* ================================================================= */}
      {/* HEADER BAR                                                        */}
      {/* ================================================================= */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#070b14]/90 backdrop-blur-md">
        <div className="mx-auto max-w-[1600px] px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/25 to-indigo-600/25 border border-sky-400/40 shadow-[0_0_20px_rgba(56,189,248,0.18)]">
              <ShieldCheck className="h-5 w-5 text-sky-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FinSec Agent
                </h1>
                <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-sky-300">
                  AI SOC &amp; Virtual Patching
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Nền tảng Điều tra Tự chủ &amp; Vá ảo Không Chặn Nhầm cho Vận hành Fintech
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-slate-300">
              <Database className="h-3.5 w-3.5 text-emerald-400" />
              <span>
                DB:{" "}
                <strong className="text-white uppercase">
                  {state?.db_mode || "..."}
                </strong>
              </span>
              <span className="text-slate-600">|</span>
              <span>
                Baseline:{" "}
                <strong className="text-emerald-300">
                  {state?.clean_baseline_count ?? 300}
                </strong>{" "}
                sạch
              </span>
            </div>

            <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/70 px-2.5 py-1.5 text-slate-300">
              <Lock className="h-3.5 w-3.5 text-sky-400" />
              <span>
                Active Rules:{" "}
                <strong
                  className={
                    (state?.active_rules_count || 0) > 0
                      ? "text-emerald-400"
                      : "text-slate-400"
                  }
                >
                  {state?.active_rules_count ?? 0}
                </strong>
              </span>
            </div>

            <button
              onClick={handleResetSandbox}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 font-medium text-slate-200 hover:bg-slate-700/90 hover:border-slate-600 transition disabled:opacity-50"
            >
              <RotateCcw
                className={`h-3.5 w-3.5 ${
                  loadingAction === "reset" ? "animate-spin" : ""
                }`}
              />
              Reset Sandbox
            </button>

            <a
              href={`${API_BASE_URL}/docs`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-1.5 font-medium text-sky-300 hover:bg-sky-500/25 transition"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              Swagger API Docs
            </a>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-4 space-y-4">
        {/* Notifications */}
        {errorMsg && (
          <div className="flex items-center justify-between gap-3 rounded-xl border border-rose-500/50 bg-rose-500/15 px-4 py-2.5 text-xs text-rose-200">
            <div className="flex items-center gap-2">
              <AlertOctagon className="h-4 w-4 shrink-0 text-rose-400" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={refreshState}
              className="rounded bg-rose-500/25 px-2 py-1 text-[11px] font-medium hover:bg-rose-500/35"
            >
              Thử lại
            </button>
          </div>
        )}

        {toastMsg && (
          <div className="flex items-center gap-2 rounded-xl border border-sky-500/40 bg-sky-500/15 px-4 py-2.5 text-xs text-sky-100 animate-step-in">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-sky-400" />
            <span>{toastMsg}</span>
          </div>
        )}

        {/* ================================================================= */}
        {/* REGION 1: TOP BAR — LIVE FINTECH ATTACK & TRAFFIC BAR             */}
        {/* ================================================================= */}
        <section className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-rose-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Live Fintech Attack &amp; Traffic Bar
              </h2>
              <span className="text-[11px] text-slate-500">
                (Bắn request HTTP thật qua Middleware Sandbox)
              </span>
            </div>

            <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs text-amber-200 select-none">
              <input
                type="checkbox"
                checked={withPromptInjection}
                onChange={(e) => setWithPromptInjection(e.target.checked)}
                className="h-3.5 w-3.5 rounded accent-amber-500"
              />
              <span>Gắn kèm Prompt Injection vào kịch bản 1–4</span>
            </label>
          </div>

          {/* Attack & Normal Traffic Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => handleSimulate("webhook_replay", "1. Webhook Replay")}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-500/25 transition disabled:opacity-50"
            >
              <Zap className="h-3.5 w-3.5 text-rose-400" />
              1. Webhook Replay
            </button>

            <button
              onClick={() => handleSimulate("bola_idor", "2. BOLA/IDOR Ví")}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-orange-500/40 bg-orange-500/15 px-3 py-2 text-xs font-semibold text-orange-200 hover:bg-orange-500/25 transition disabled:opacity-50"
            >
              <UserCheck className="h-3.5 w-3.5 text-orange-400" />
              2. BOLA/IDOR Ví
            </button>

            <button
              onClick={() => handleSimulate("leaked_key", "3. Lộ Internal Key")}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/15 px-3 py-2 text-xs font-semibold text-amber-200 hover:bg-amber-500/25 transition disabled:opacity-50"
            >
              <KeyRound className="h-3.5 w-3.5 text-amber-400" />
              3. Lộ Internal Key
            </button>

            <button
              onClick={() => handleSimulate("race_condition", "4. Race Condition")}
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-fuchsia-500/40 bg-fuchsia-500/15 px-3 py-2 text-xs font-semibold text-fuchsia-200 hover:bg-fuchsia-500/25 transition disabled:opacity-50"
            >
              <Activity className="h-3.5 w-3.5 text-fuchsia-400" />
              4. Race Condition
            </button>

            <button
              onClick={() =>
                handleSimulate("prompt_injection", "5. Prompt Injection qua Log")
              }
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/60 bg-red-600/20 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-600/35 transition disabled:opacity-50"
            >
              <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
              5. Kèm Prompt Injection qua Log
            </button>

            <div className="h-6 w-px bg-slate-800 mx-1 hidden lg:block" />

            <button
              onClick={() =>
                handleSimulate("normal_traffic", "Giao dịch khách hàng bình thường")
              }
              disabled={loadingAction !== null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/20 px-3.5 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/30 transition disabled:opacity-50"
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              Gửi giao dịch khách hàng bình thường
            </button>

            <button
              onClick={handleInvestigate}
              disabled={loadingAction !== null}
              className="ml-auto inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-sky-500 to-indigo-500 px-4 py-2 text-xs font-bold text-white shadow-[0_0_20px_rgba(56,189,248,0.3)] hover:from-sky-400 hover:to-indigo-400 transition disabled:opacity-50"
            >
              {loadingAction === "investigate" ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Cpu className="h-3.5 w-3.5" />
              )}
              {loadingAction === "investigate"
                ? "AI Agent đang điều tra..."
                : "Chạy AI SOC Điều tra"}
            </button>
          </div>

          {/* Live Wallets + Last HTTP Response Status Strip */}
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 pt-1">
            {/* 5 Wallets Live Balance */}
            <div className="xl:col-span-7 grid grid-cols-2 sm:grid-cols-5 gap-2">
              {(state?.wallets || []).map((w) => {
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

            {/* Last Traffic Burst Result (200 OK vs 403/429 Blocked) */}
            <div className="xl:col-span-5 rounded-xl border border-slate-800 bg-[#090f1d] px-3 py-2 flex flex-col justify-center">
              {!lastSim ? (
                <div className="text-xs text-slate-500 flex items-center gap-2">
                  <Play className="h-3.5 w-3.5 text-slate-600" />
                  <span>
                    Chưa gửi traffic. Bấm 1 trong 5 nút tấn công hoặc nút giao dịch sạch ở trên để kiểm thử Live Middleware.
                  </span>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-semibold text-slate-300">
                      Kết quả gần nhất:{" "}
                      <span className="font-mono text-sky-300">
                        {lastSim.scenario}
                      </span>
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 font-mono text-emerald-300 border border-emerald-500/30">
                        200 OK: {lastSim.succeeded_200}
                      </span>
                      <span className="rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-rose-300 border border-rose-500/30">
                        403/429 Blocked: {lastSim.blocked_count}
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {lastSim.results.map((r) => (
                      <span
                        key={r.seq}
                        title={JSON.stringify(r.response)}
                        className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] font-semibold border ${
                          r.blocked
                            ? "bg-rose-500/20 text-rose-200 border-rose-500/50"
                            : r.status_code === 200
                            ? "bg-emerald-500/20 text-emerald-200 border-emerald-500/50"
                            : "bg-amber-500/20 text-amber-200 border-amber-500/50"
                        }`}
                      >
                        #{r.seq} {r.method} {r.status_code}
                        {r.blocked ? " BLOCKED" : " OK"}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ================================================================= */}
        {/* MAIN 2-COLUMN WORKSPACE                                           */}
        {/* ================================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* =============================================================== */}
          {/* REGION 2 (LEFT): AI AGENT LIVE INVESTIGATION TRACE              */}
          {/* =============================================================== */}
          <section className="lg:col-span-6 space-y-4">
            <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-sky-400" />
                  <h2 className="text-sm font-bold text-white">
                    Luồng điều tra của AI Agent (Live Investigation Trace)
                  </h2>
                </div>
                {activeIncident && (
                  <span className="font-mono text-[11px] text-slate-400">
                    {activeIncident.id} ·{" "}
                    <span className="text-sky-400">
                      {activeIncident.engine_used || state?.llm_model}
                    </span>
                  </span>
                )}
              </div>

              {!activeIncident ? (
                <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d]/70 p-8 text-center space-y-3">
                  <ShieldAlert className="h-10 w-10 text-slate-600 mx-auto" />
                  <div className="space-y-1">
                    <p className="text-sm font-semibold text-slate-300">
                      AI SOC Agent đang trực chiến
                    </p>
                    <p className="text-xs text-slate-500 max-w-md mx-auto">
                      Hãy kích hoạt 1 kịch bản tấn công trên thanh trên cùng (ví dụ{" "}
                      <span className="text-rose-300 font-mono">1. Webhook Replay</span>{" "}
                      hoặc{" "}
                      <span className="text-red-300 font-mono">
                        5. Prompt Injection
                      </span>
                      ), sau đó bấm{" "}
                      <strong className="text-sky-300">Chạy AI SOC Điều tra</strong> để
                      xem Agent tự gọi 4 công cụ DB và chạy Dry-Run.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* CRITICAL RED BANNER FOR INDIRECT PROMPT INJECTION */}
                  {activeIncident.prompt_injection_detected && (
                    <div className="rounded-xl border-2 border-red-500 bg-red-950/60 p-3.5 shadow-[0_0_24px_rgba(239,68,68,0.3)] animate-pulse">
                      <div className="flex items-start gap-2.5">
                        <AlertOctagon className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
                        <div className="space-y-1 text-xs">
                          <div className="font-bold uppercase tracking-wider text-red-300">
                            CẢNH BÁO CRITICAL: PHÁT HIỆN INDIRECT PROMPT INJECTION QUA LOG!
                          </div>
                          <p className="text-red-100/90 leading-relaxed">
                            Kẻ tấn công đã nhúng mệnh lệnh giả mạo vào HTTP log nhằm đánh lừa AI SOC bỏ qua sự cố &amp; whitelist IP. Lớp{" "}
                            <code className="rounded bg-red-900/80 px-1 py-0.5 font-mono text-red-200">
                              sanitizer.py
                            </code>{" "}
                            đã phát hiện, cắt ngắn chuỗi độc hại và cô lập hoàn toàn trong thẻ{" "}
                            <code className="rounded bg-red-900/80 px-1 py-0.5 font-mono text-red-200">
                              &lt;UNTRUSTED_RAW_LOG_DATA&gt;
                            </code>
                            .
                          </p>
                          {activeIncident.prompt_injection_evidence &&
                            activeIncident.prompt_injection_evidence.length > 0 && (
                              <div className="mt-1.5 rounded bg-black/40 border border-red-500/30 p-2 font-mono text-[11px] text-red-200 break-all">
                                Patterns:{" "}
                                {activeIncident.prompt_injection_evidence[0].patterns.join(
                                  ", "
                                )}{" "}
                                | Excerpt: &quot;
                                {activeIncident.prompt_injection_evidence[0].excerpt}
                                &quot;
                              </div>
                            )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Incident Header + OWASP API Top 10 Tag */}
                  <div className="rounded-xl border border-slate-800 bg-[#090f1d] p-3.5 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded-md border px-2 py-0.5 text-[11px] font-bold uppercase ${
                          SEVERITY_STYLES[activeIncident.severity] ||
                          SEVERITY_STYLES.HIGH
                        }`}
                      >
                        {activeIncident.severity}
                      </span>
                      <span className="rounded-md border border-indigo-500/40 bg-indigo-500/15 px-2 py-0.5 font-mono text-[11px] text-indigo-200">
                        {activeIncident.owasp_tag}
                      </span>
                      <span
                        className={`ml-auto rounded-md border px-2 py-0.5 text-[11px] font-bold ${
                          currentProposedRule?.status === "ACTIVE" ||
                          activeIncident.status === "MITIGATED"
                            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                            : "border-rose-500/40 bg-rose-500/15 text-rose-300"
                        }`}
                      >
                        {currentProposedRule?.status === "ACTIVE"
                          ? "MITIGATED (VIRTUAL PATCH ACTIVE)"
                          : activeIncident.status}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-white">
                      {activeIncident.title}
                    </h3>
                    {activeIncident.summary && (
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {activeIncident.summary}
                      </p>
                    )}
                  </div>

                  {/* Step-by-step ReAct Tool Calling Trace */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
                      ReAct Function Calling Trace ({visibleStepsCount}/
                      {activeIncident.reasoning_trace.length} bước)
                    </div>
                    <div className="space-y-2">
                      {activeIncident.reasoning_trace
                        .slice(0, visibleStepsCount)
                        .map((s) => (
                          <div
                            key={s.step}
                            className="animate-step-in rounded-xl border border-slate-800 bg-[#090f1d] p-3 space-y-1.5"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-sky-500/20 border border-sky-500/40 font-mono text-[10px] font-bold text-sky-300">
                                  {s.step}
                                </span>
                                <span className="font-mono text-xs font-bold text-sky-300">
                                  {s.action}()
                                </span>
                              </div>
                              <code className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-400 max-w-full truncate">
                                {JSON.stringify(s.args)}
                              </code>
                            </div>
                            <p className="text-xs text-slate-300 pl-7 leading-relaxed">
                              {s.observation_summary}
                            </p>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* Attack Kill Chain Timeline */}
                  {activeIncident.attack_timeline?.length > 0 && (
                    <div className="space-y-2">
                      <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
                        Attack Kill Chain Timeline
                      </div>
                      <div className="rounded-xl border border-slate-800 bg-[#090f1d] p-3 space-y-2">
                        {activeIncident.attack_timeline.slice(0, 6).map((ev, idx) => (
                          <div
                            key={idx}
                            className="flex items-start gap-2.5 text-xs border-l-2 border-rose-500/40 pl-3 py-0.5"
                          >
                            <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-300 shrink-0">
                              {ev.stage}
                            </span>
                            <div className="min-w-0 flex-1">
                              <div className="font-mono text-[11px] text-slate-200 truncate">
                                {ev.detail}
                              </div>
                              <div className="text-[10px] text-slate-500 font-mono">
                                IP: {ev.ip_address || "N/A"} ·{" "}
                                {ev.timestamp.slice(11, 19)} UTC
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

            {/* Live Non-Baseline HTTP Log Feed */}
            <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Activity className="h-3.5 w-3.5 text-sky-400" />
                  Live Sandbox HTTP Logs (Mới nhất từ DB)
                </h3>
                <span className="text-[11px] text-slate-500">
                  {state?.recent_logs.length ?? 0} live events
                </span>
              </div>
              <div className="max-h-56 overflow-y-auto rounded-xl border border-slate-800 bg-[#070b14]">
                {!state?.recent_logs.length ? (
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
                      {state.recent_logs.slice(0, 15).map((log) => (
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
          </section>

          {/* =============================================================== */}
          {/* REGION 3 (RIGHT): HUMAN-IN-THE-LOOP MITIGATION & DRY-RUN        */}
          {/* =============================================================== */}
          <section className="lg:col-span-6 space-y-4">
            <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <h2 className="text-sm font-bold text-white">
                    Phản ứng &amp; Kiểm định An toàn (Human-in-the-Loop Mitigation)
                  </h2>
                </div>
                {currentProposedRule && (
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold border ${
                      currentProposedRule.status === "ACTIVE"
                        ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                        : currentProposedRule.status === "ROLLED_BACK"
                        ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                        : "bg-slate-800 text-slate-300 border-slate-700"
                    }`}
                  >
                    RULE: {currentProposedRule.status}
                  </span>
                )}
              </div>

              {/* PROMINENT DRY-RUN BLAST RADIUS CARD */}
              <div
                className={`rounded-xl border p-4 space-y-3 ${
                  dryRun
                    ? dryRun.blocked_clean === 0
                      ? "border-emerald-500/45 bg-gradient-to-br from-emerald-950/40 to-[#090f1d]"
                      : "border-rose-500/50 bg-rose-950/30"
                    : "border-slate-800 bg-[#090f1d]"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Kết quả Kiểm định Dry-Run (Chạy thật trên DB Baseline)
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

                {!dryRun ? (
                  <p className="text-xs text-slate-500">
                    Chưa có báo cáo Dry-Run. Khi AI Agent điều tra sự cố, luật phòng thủ sẽ được chạy mô phỏng trên toàn bộ{" "}
                    <strong className="text-slate-300">
                      {state?.clean_baseline_count ?? 300} giao dịch hợp lệ lịch sử
                    </strong>{" "}
                    trước khi trình duyệt.
                  </p>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="rounded-lg border border-slate-800 bg-black/35 p-3">
                      <div className="text-[11px] text-slate-400">
                        Hiệu quả Chặn tấn công (Attack Blocked)
                      </div>
                      <div className="mt-1 flex items-baseline gap-2">
                        <span className="text-2xl font-extrabold font-mono text-sky-300">
                          {dryRun.attack_blocked_rate}%
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          ({dryRun.blocked_attack_logs}/{dryRun.total_attack_logs} req)
                        </span>
                      </div>
                    </div>

                    <div className="rounded-lg border border-slate-800 bg-black/35 p-3">
                      <div className="text-[11px] text-slate-400">
                        Chặn nhầm khách thật (False Positives)
                      </div>
                      <div className="mt-1 flex items-baseline gap-2">
                        <span
                          className={`text-2xl font-extrabold font-mono ${
                            dryRun.blocked_clean === 0
                              ? "text-emerald-400"
                              : "text-rose-400"
                          }`}
                        >
                          {dryRun.blocked_clean} / {dryRun.total_clean}
                        </span>
                        <span className="text-xs font-semibold text-emerald-300">
                          {dryRun.blocked_clean === 0 ? "(An toàn)" : "(Cần chỉnh)"}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* 3 TABS: Virtual Patch Policy | Hotfix Code Diff | Raw API & cURL */}
              <div className="flex items-center gap-1 rounded-xl border border-slate-800 bg-[#070b14] p-1 text-xs">
                <button
                  onClick={() => setActiveTab("policy")}
                  className={`flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 font-semibold transition ${
                    activeTab === "policy"
                      ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <ShieldCheck className="h-3.5 w-3.5" />
                  1. Virtual Patch Policy
                </button>
                <button
                  onClick={() => setActiveTab("diff")}
                  className={`flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 font-semibold transition ${
                    activeTab === "diff"
                      ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Code2 className="h-3.5 w-3.5" />
                  2. Hotfix Code Diff
                </button>
                <button
                  onClick={() => setActiveTab("api")}
                  className={`flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 font-semibold transition ${
                    activeTab === "api"
                      ? "bg-sky-500/20 text-sky-200 border border-sky-500/40"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Terminal className="h-3.5 w-3.5" />
                  3. Raw API &amp; cURL
                </button>
              </div>

              {/* TAB 1: VIRTUAL PATCH POLICY */}
              {activeTab === "policy" && (
                <div className="space-y-3">
                  {!currentProposedRule ? (
                    <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d] p-6 text-center text-xs text-slate-500">
                      Chưa có luật Virtual Patch nào được đề xuất. Chạy AI SOC Điều tra để sinh luật JSON an toàn (không dùng eval/exec).
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

                      {/* Big Enforce / Rollback Button */}
                      <button
                        onClick={handleEnforceOrRollback}
                        disabled={loadingAction !== null}
                        className={`w-full inline-flex items-center justify-center gap-2 rounded-xl px-4 py-3.5 text-sm font-bold transition shadow-lg disabled:opacity-50 ${
                          currentProposedRule.status === "ACTIVE"
                            ? "bg-gradient-to-r from-amber-600 to-rose-600 hover:from-amber-500 hover:to-rose-500 text-white shadow-rose-500/20"
                            : "bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white shadow-emerald-500/25"
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

                      {currentProposedRule.status === "ACTIVE" && (
                        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-200 leading-relaxed">
                          <strong>Luật đang hoạt động thật trong Middleware (&lt;5ms)!</strong>{" "}
                          Hãy bấm lại nút tấn công ở thanh trên để kiểm chứng request bị chặn{" "}
                          <code className="font-mono font-bold text-rose-300">
                            403/429 BLOCKED
                          </code>
                          , sau đó bấm{" "}
                          <strong className="text-emerald-300">
                            Gửi giao dịch khách hàng bình thường
                          </strong>{" "}
                          để chứng minh khách thật vẫn nhận{" "}
                          <code className="font-mono font-bold text-emerald-300">
                            200 OK
                          </code>
                          .
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* TAB 2: HOTFIX CODE DIFF */}
              {activeTab === "diff" && (
                <div className="space-y-3">
                  {!activeIncident?.hotfix_diff ? (
                    <div className="rounded-xl border border-dashed border-slate-800 bg-[#090f1d] p-6 text-center text-xs text-slate-500">
                      Chưa có Hotfix Code Diff. Chạy AI SOC Điều tra để nhận bản vá mã nguồn gốc cho kỹ sư Fintech.
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">
                          Đề xuất vá triệt để tại mã nguồn dịch vụ thanh toán:
                        </span>
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

              {/* TAB 3: RAW API & cURL */}
              {activeTab === "api" && (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-300">
                        cURL Commands (X-API-Key: {DEMO_API_KEY})
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

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-300">
                        Raw JSON Response (/v1/incidents/investigate)
                      </span>
                      {activeIncident && (
                        <button
                          onClick={() =>
                            handleCopy(
                              "rawjson",
                              JSON.stringify(activeIncident, null, 2)
                            )
                          }
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700"
                        >
                          <Copy className="h-3 w-3" />
                          {copiedKey === "rawjson" ? "Đã copy!" : "Copy JSON"}
                        </button>
                      )}
                    </div>
                    <pre className="max-h-72 overflow-auto rounded-xl border border-slate-800 bg-[#05080f] p-3 font-mono text-[11px] text-slate-300 leading-relaxed">
                      {activeIncident
                        ? JSON.stringify(activeIncident, null, 2)
                        : "// Chưa có dữ liệu phản hồi. Bấm 'Chạy AI SOC Điều tra' để xem nguyên văn JSON."}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
