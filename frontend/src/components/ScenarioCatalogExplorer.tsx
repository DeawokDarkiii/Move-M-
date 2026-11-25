"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  Flame,
  Layers,
  Play,
  Search,
  Shuffle,
  Sliders,
} from "lucide-react";
import {
  fetchScenarioCatalog,
  ScenarioCatalogItem,
  ScenarioCatalogResponse,
} from "@/lib/api";

interface ScenarioCatalogExplorerProps {
  loadingAction: string | null;
  onRunScenario: (payload: {
    scenario_id?: string;
    total_transactions?: number;
    vectors?: string[];
    attack_ratio_pct?: number;
    with_prompt_injection?: boolean;
  }) => void;
}

const ALL_VECTORS = [
  { id: "webhook_replay", label: "Webhook Replay" },
  { id: "bola_idor", label: "BOLA / IDOR" },
  { id: "leaked_key", label: "Lộ Internal Key" },
  { id: "race_condition", label: "Race Condition" },
  { id: "credential_stuffing", label: "Credential Stuffing (ATO)" },
  { id: "parameter_tampering", label: "Parameter Tampering" },
  { id: "ssrf_callback", label: "SSRF (Capital One)" },
];

export function ScenarioCatalogExplorer({
  loadingAction,
  onRunScenario,
}: ScenarioCatalogExplorerProps) {
  const [catalog, setCatalog] = useState<ScenarioCatalogResponse | null>(null);
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [scaleTier, setScaleTier] = useState("");
  const [vectorFilter, setVectorFilter] = useState("");
  const [page, setPage] = useState(1);
  const [loadingList, setLoadingList] = useState(false);

  // Custom High-Volume Multi-Vector Builder
  const [customTx, setCustomTx] = useState(25000);
  const [customRatio, setCustomRatio] = useState(3.2);
  const [customVectors, setCustomVectors] = useState<string[]>([
    "webhook_replay",
    "bola_idor",
    "leaked_key",
    "race_condition",
  ]);
  const [customPI, setCustomPI] = useState(true);

  const loadCatalog = useCallback(async () => {
    setLoadingList(true);
    try {
      const data = await fetchScenarioCatalog({
        q,
        category,
        scale_tier: scaleTier,
        vector: vectorFilter,
        page,
        page_size: 12,
      });
      setCatalog(data);
    } catch {
      // ignore transient error
    } finally {
      setLoadingList(false);
    }
  }, [q, category, scaleTier, vectorFilter, page]);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog]);

  const toggleCustomVector = (vec: string) => {
    setCustomVectors((prev) =>
      prev.includes(vec)
        ? prev.length > 1
          ? prev.filter((v) => v !== vec)
          : prev
        : [...prev, vec]
    );
  };

  return (
    <div className="space-y-5">
      {/* Custom High-Volume Stress & Multi-Vector Builder */}
      <div className="rounded-2xl border border-indigo-500/35 bg-gradient-to-br from-indigo-950/30 via-[#0d1424] to-[#0d1424] p-4 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="h-4 w-4 text-indigo-400" />
              Bộ Tạo Traffic Thực tế Tùy chỉnh (1.000 – 100.000 Giao dịch · Kết hợp Đa tấn công)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Tự cấu hình quy mô giao dịch, tỷ lệ tấn công ngẫu nhiên và chọn nhiều mũi tấn công diễn ra cùng lúc như vận hành thật.
            </p>
          </div>
          <button
            onClick={() => onRunScenario({ scenario_id: "random" })}
            disabled={loadingAction !== null}
            className="inline-flex items-center gap-1.5 rounded-xl bg-sky-500/20 border border-sky-500/40 px-3 py-2 text-xs font-bold text-sky-200 hover:bg-sky-500/30 transition disabled:opacity-50"
          >
            <Shuffle className="h-3.5 w-3.5" />
            Bốc Ngẫu nhiên 1 / 900 Kịch bản
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          <div className="lg:col-span-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">Quy mô giao dịch</span>
              <span className="font-mono font-bold text-sky-300">
                {customTx.toLocaleString("vi-VN")} GD
              </span>
            </div>
            <input
              type="range"
              min={2000}
              max={100000}
              step={1000}
              value={customTx}
              onChange={(e) => setCustomTx(Number(e.target.value))}
              className="w-full accent-sky-500"
            />
            <div className="flex justify-between text-[10px] font-mono text-slate-500">
              <span>2,000</span>
              <span>25,000</span>
              <span>50,000</span>
              <span>100,000</span>
            </div>
          </div>

          <div className="lg:col-span-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">Tỷ lệ tấn công trộn lẫn</span>
              <span className="font-mono font-bold text-rose-300">{customRatio}%</span>
            </div>
            <input
              type="range"
              min={0.5}
              max={15}
              step={0.5}
              value={customRatio}
              onChange={(e) => setCustomRatio(Number(e.target.value))}
              className="w-full accent-rose-500"
            />
            <div className="text-[10px] font-mono text-slate-500">
              ≈ {Math.round((customTx * customRatio) / 100).toLocaleString("vi-VN")} request độc hại ngẫu nhiên
            </div>
          </div>

          <div className="lg:col-span-5 space-y-2">
            <div className="flex flex-wrap gap-1.5">
              {ALL_VECTORS.map((v) => {
                const active = customVectors.includes(v.id);
                return (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() => toggleCustomVector(v.id)}
                    className={`rounded-lg px-2.5 py-1.5 text-[11px] font-semibold border transition ${
                      active
                        ? "bg-rose-500/20 border-rose-500/50 text-rose-200"
                        : "bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {active ? "✓ " : "+ "}
                    {v.label}
                  </button>
                );
              })}
              <button
                type="button"
                onClick={() => setCustomPI((p) => !p)}
                className={`rounded-lg px-2.5 py-1.5 text-[11px] font-semibold border transition ${
                  customPI
                    ? "bg-fuchsia-500/20 border-fuchsia-500/50 text-fuchsia-200"
                    : "bg-slate-900 border-slate-700 text-slate-400"
                }`}
              >
                {customPI ? "✓ " : "+ "}Prompt Injection
              </button>
            </div>

            <button
              onClick={() =>
                onRunScenario({
                  total_transactions: customTx,
                  vectors: customVectors,
                  attack_ratio_pct: customRatio,
                  with_prompt_injection: customPI,
                })
              }
              disabled={loadingAction !== null}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-rose-600 to-indigo-600 hover:from-rose-500 hover:to-indigo-500 px-4 py-2.5 text-xs font-bold text-white shadow-lg transition disabled:opacity-50"
            >
              <Flame className="h-4 w-4" />
              {loadingAction === "scale"
                ? "Đang chạy mô phỏng..."
                : `Chạy Mô phỏng ${customTx.toLocaleString("vi-VN")} Giao dịch (${customVectors.length} mũi tấn công)`}
            </button>
          </div>
        </div>
      </div>

      {/* 900-Scenario Searchable & Filterable Catalog */}
      <div className="rounded-2xl border border-slate-800 bg-[#0d1424]/95 p-4 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-sky-400" />
              Kho 900 Kịch bản Vận hành &amp; Tấn công Fintech Thực tế
            </h3>
            <p className="text-xs text-slate-400">
              Hiển thị{" "}
              <strong className="text-white">
                {catalog?.total_filtered ?? 900} / {catalog?.total_catalog ?? 900}
              </strong>{" "}
              kịch bản (15 bối cảnh vận hành × 12 tổ hợp tấn công × 5 cấp độ lưu lượng 2k–60k GD).
            </p>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(1);
              }}
              placeholder="Tìm mã SCN-0123, Payday, Flash Sale..."
              className="w-full rounded-xl border border-slate-700 bg-[#070b14] pl-8 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
            />
          </div>

          <select
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-slate-700 bg-[#070b14] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          >
            <option value="">Tất cả loại kịch bản (900)</option>
            <option value="single_vector">Đơn mũi tấn công (300)</option>
            <option value="multi_vector">Kết hợp đa mũi 2–3 lớp (450)</option>
            <option value="red_team_blitz">Tổng lực Red Team 4–5 mũi (150)</option>
          </select>

          <select
            value={scaleTier}
            onChange={(e) => {
              setScaleTier(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-slate-700 bg-[#070b14] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          >
            <option value="">Tất cả quy mô giao dịch</option>
            <option value="standard">Ca chuẩn (2k – 5k GD)</option>
            <option value="high">Cao tải (8k – 15k GD)</option>
            <option value="peak">Giờ cao điểm (18k – 30k GD)</option>
            <option value="surge">Đột biến Payday (32k – 45k GD)</option>
            <option value="mega">Siêu tải Thực tế (46k – 60k GD)</option>
          </select>

          <select
            value={vectorFilter}
            onChange={(e) => {
              setVectorFilter(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-slate-700 bg-[#070b14] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
          >
            <option value="">Tất cả 7 mũi tấn công lịch sử</option>
            <option value="webhook_replay">Webhook Replay</option>
            <option value="bola_idor">BOLA / IDOR</option>
            <option value="leaked_key">Lộ Internal Key</option>
            <option value="race_condition">Race Condition (TOCTOU)</option>
            <option value="credential_stuffing">Credential Stuffing / ATO (PayPal)</option>
            <option value="parameter_tampering">Parameter Tampering / Mass Assignment</option>
            <option value="ssrf_callback">SSRF Cloud Metadata (Capital One)</option>
            <option value="prompt_injection">Kèm Prompt Injection</option>
          </select>
        </div>

        {/* Paginated Scenario Grid */}
        {loadingList && !catalog ? (
          <div className="p-8 text-center text-xs text-slate-400">
            Đang tải danh mục 900 kịch bản...
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {(catalog?.items || []).map((scn: ScenarioCatalogItem) => (
              <div
                key={scn.id}
                className="rounded-xl border border-slate-800 bg-[#070b14] p-3.5 flex flex-col justify-between gap-3 hover:border-sky-500/40 transition"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="rounded bg-slate-900 border border-slate-700 px-2 py-0.5 font-mono text-[10px] font-bold text-sky-300">
                      {scn.id}
                    </span>
                    <span className="font-mono text-[11px] font-bold text-emerald-300">
                      {scn.total_transactions.toLocaleString("vi-VN")} GD
                    </span>
                  </div>

                  <div className="text-xs font-bold text-white leading-snug">
                    {scn.name}
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {scn.vectors.map((v) => (
                      <span
                        key={v}
                        className="rounded bg-rose-500/15 border border-rose-500/30 px-1.5 py-0.5 font-mono text-[10px] text-rose-200"
                      >
                        {v}
                      </span>
                    ))}
                    {scn.with_prompt_injection && (
                      <span className="rounded bg-fuchsia-500/15 border border-fuchsia-500/35 px-1.5 py-0.5 font-mono text-[10px] text-fuchsia-200">
                        +PI
                      </span>
                    )}
                  </div>

                  <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                    {scn.description}
                  </p>
                </div>

                <div className="flex items-center justify-between border-t border-slate-800/80 pt-2.5">
                  <span className="text-[10px] font-mono text-slate-500">
                    ~{scn.estimated_attacks?.toLocaleString("vi-VN")} tấn công ({scn.attack_ratio_pct}%)
                  </span>
                  <button
                    onClick={() => onRunScenario({ scenario_id: scn.id })}
                    disabled={loadingAction !== null}
                    className="inline-flex items-center gap-1 rounded-lg bg-sky-500/20 border border-sky-500/40 px-2.5 py-1 text-[11px] font-bold text-sky-200 hover:bg-sky-500/30 transition disabled:opacity-50"
                  >
                    <Play className="h-3 w-3" />
                    Chạy ngay
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {catalog && catalog.total_pages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-800 pt-3 text-xs">
            <span className="text-slate-400">
              Trang <strong className="text-white">{catalog.page}</strong> /{" "}
              {catalog.total_pages} ({catalog.total_filtered} kịch bản)
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                Trước
              </button>
              <button
                onClick={() => setPage((p) => Math.min(catalog.total_pages, p + 1))}
                disabled={page >= catalog.total_pages}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                Sau
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
