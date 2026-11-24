export interface Wallet {
  id: string;
  owner_id: string;
  balance: number;
}

export interface ApiLog {
  id: number;
  method: string;
  path: string;
  status_code: number;
  ip_address: string;
  user_agent?: string | null;
  actor_id?: string | null;
  api_key_id?: string | null;
  request_body: Record<string, unknown>;
  is_clean_baseline: boolean;
  created_at: string;
}

export interface RuleSpec {
  target_path_prefix: string;
  condition_type:
    | "DEDUP_BODY_FIELD"
    | "ENFORCE_OWNER_MATCH"
    | "IP_WHITELIST_FOR_KEY"
    | "CONCURRENCY_LOCK"
    | "IP_BLOCKLIST";
  params: Record<string, unknown>;
  action: "BLOCK_403" | "BLOCK_429";
  reason: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  status: "DRAFT" | "ACTIVE" | "ROLLED_BACK";
  rule_spec: RuleSpec;
  created_at?: string;
}

export interface ReasoningStep {
  step: number;
  action: string;
  args: Record<string, unknown>;
  observation_summary: string;
}

export interface TimelineEvent {
  timestamp: string;
  stage: string;
  detail: string;
  ip_address?: string;
  endpoint?: string;
  status_code?: number;
}

export interface DryRunReport {
  valid?: boolean;
  total_clean: number;
  blocked_clean: number;
  false_positive_rate: number;
  total_attack_logs: number;
  blocked_attack_logs: number;
  attack_blocked_rate: number;
  attack_blocked: boolean;
  safe_to_enforce: boolean;
  sample_false_positives?: Array<Record<string, unknown>>;
  evaluated_at?: string;
}

export interface PromptInjectionEvidence {
  log_id?: number;
  ip_address?: string;
  path?: string;
  patterns: string[];
  excerpt: string;
}

export interface ExecutiveSummaryAnalysis {
  headline: string;
  category_vi: string;
  severity: string;
  status: string;
  what_happened: string;
  plain_language_analogy: string;
  business_impact: string;
  protection_status: string;
  blast_radius_verdict: string;
  prompt_injection_warning: string;
}

export interface TechnicalDeepDiveAnalysis {
  owasp_api_top_10: string;
  cwe_mapping: string;
  mitre_attack: string;
  cvss_v31_estimate: string;
  condition_type: string;
  root_cause_analysis: string;
  virtual_patch_mechanism: string;
  remediation_checklist: string[];
  engine_used: string;
}

export interface StructuredIncidentAnalysis {
  generated_at: string;
  executive_summary: ExecutiveSummaryAnalysis;
  technical_analysis: TechnicalDeepDiveAnalysis;
}

export interface IncidentReport {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  owasp_tag: string;
  summary?: string;
  reasoning_trace: ReasoningStep[];
  attack_timeline: TimelineEvent[];
  proposed_rule: PolicyRule | null;
  dry_run_report: DryRunReport | null;
  hotfix_diff: string | null;
  status: "OPEN" | "MITIGATED";
  prompt_injection_detected?: boolean;
  prompt_injection_evidence?: PromptInjectionEvidence[];
  engine_used?: string;
  created_at?: string;
  structured_analysis?: StructuredIncidentAnalysis;
}

export interface SandboxState {
  db_mode: string;
  llm_configured: boolean;
  llm_model: string;
  clean_baseline_count: number;
  wallets: Wallet[];
  active_rules_count: number;
  policy_rules: PolicyRule[];
  recent_logs: ApiLog[];
  incidents: IncidentReport[];
}

export interface SimulationResultItem {
  seq: number;
  label?: string;
  method: string;
  path: string;
  status_code: number;
  blocked: boolean;
  response: Record<string, unknown>;
}

export interface SimulationResponse {
  scenario: string;
  with_prompt_injection: boolean;
  total_requests: number;
  succeeded_200: number;
  blocked_count: number;
  results: SimulationResultItem[];
  wallets: Wallet[];
}

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
).replace(/\/+$/, "");

export const DEMO_API_KEY =
  process.env.NEXT_PUBLIC_FINSEC_API_KEY || "finsec-demo-key-2026";

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  baseUrl: string = API_BASE_URL
): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": DEMO_API_KEY,
      ...(options.headers || {}),
    },
    cache: "no-store",
  });

  if (!res.ok) {
    let errText = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      errText = data?.detail || JSON.stringify(data);
    } catch {
      errText = await res.text();
    }
    throw new Error(errText);
  }
  return res.json() as Promise<T>;
}

export function fetchSandboxState(baseUrl?: string): Promise<SandboxState> {
  return apiFetch<SandboxState>("/v1/sandbox/state", { method: "GET" }, baseUrl);
}

export function triggerSimulation(
  scenario:
    | "webhook_replay"
    | "bola_idor"
    | "leaked_key"
    | "race_condition"
    | "prompt_injection"
    | "normal_traffic",
  withPromptInjection = false,
  baseUrl?: string
): Promise<SimulationResponse> {
  return apiFetch<SimulationResponse>(
    `/v1/sandbox/simulate/${scenario}`,
    {
      method: "POST",
      body: JSON.stringify({ with_prompt_injection: withPromptInjection }),
    },
    baseUrl
  );
}

export function runAiInvestigation(
  triggerMessage?: string,
  baseUrl?: string
): Promise<IncidentReport> {
  return apiFetch<IncidentReport>(
    "/v1/incidents/investigate",
    {
      method: "POST",
      body: JSON.stringify(
        triggerMessage ? { trigger_message: triggerMessage } : {}
      ),
    },
    baseUrl
  );
}

export function enforcePolicyRule(
  ruleId: string,
  baseUrl?: string
): Promise<{ status: string; rule: PolicyRule; message: string }> {
  return apiFetch(
    `/v1/policies/${encodeURIComponent(ruleId)}/enforce`,
    { method: "POST" },
    baseUrl
  );
}

export function rollbackPolicyRule(
  ruleId: string,
  baseUrl?: string
): Promise<{ status: string; rule: PolicyRule; message: string }> {
  return apiFetch(
    `/v1/policies/${encodeURIComponent(ruleId)}/rollback`,
    { method: "POST" },
    baseUrl
  );
}

export function resetSandboxApi(
  baseUrl?: string
): Promise<{
  status: string;
  wallets_restored: number;
  clean_baseline_preserved: number;
  active_rules_cleared: boolean;
}> {
  return apiFetch("/v1/sandbox/reset", { method: "POST" }, baseUrl);
}

export async function fetchIncidentExport(
  incidentId: string,
  format: "markdown" | "html" | "json",
  baseUrl: string = API_BASE_URL
): Promise<{ content: string; filename: string; mimeType: string }> {
  const res = await fetch(
    `${baseUrl}/v1/incidents/${encodeURIComponent(incidentId)}/export?format=${format}`,
    {
      method: "GET",
      headers: {
        "X-API-Key": DEMO_API_KEY,
      },
      cache: "no-store",
    }
  );
  if (!res.ok) {
    throw new Error(`Export failed (HTTP ${res.status})`);
  }
  const content = await res.text();
  const ext = format === "markdown" ? "md" : format;
  const mimeType =
    format === "markdown"
      ? "text/markdown;charset=utf-8"
      : format === "html"
      ? "text/html;charset=utf-8"
      : "application/json;charset=utf-8";
  return {
    content,
    filename: `finsec-report-${incidentId}.${ext}`,
    mimeType,
  };
}

export function formatVnd(amount: number): string {
  return new Intl.NumberFormat("vi-VN").format(amount) + "₫";
}
