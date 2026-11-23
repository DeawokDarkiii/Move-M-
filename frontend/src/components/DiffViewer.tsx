"use client";

import React from "react";

interface DiffViewerProps {
  diff: string;
}

export function DiffViewer({ diff }: DiffViewerProps) {
  const lines = diff.split("\n");

  return (
    <div className="rounded-lg border border-slate-800 bg-[#05080f] overflow-hidden font-mono text-xs leading-relaxed">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] text-slate-400">
        <span>backend/app/sandbox/payment_api.py</span>
        <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-emerald-300 border border-emerald-500/30">
          GitHub Unified Hotfix Diff
        </span>
      </div>
      <div className="overflow-x-auto p-2">
        {lines.map((line, i) => {
          let rowClass = "text-slate-300";
          let gutter = " ";
          if (line.startsWith("+++") || line.startsWith("---")) {
            rowClass = "text-slate-400 font-semibold bg-slate-900/50";
          } else if (line.startsWith("@@")) {
            rowClass = "text-sky-300 bg-sky-500/10";
          } else if (line.startsWith("+")) {
            rowClass = "text-emerald-200 bg-emerald-500/15 border-l-2 border-emerald-400";
            gutter = "+";
          } else if (line.startsWith("-")) {
            rowClass = "text-rose-200 bg-rose-500/15 border-l-2 border-rose-400";
            gutter = "-";
          }

          return (
            <div
              key={i}
              className={`flex whitespace-pre px-2 py-0.5 ${rowClass}`}
            >
              <span className="w-7 shrink-0 select-none text-right pr-2 text-slate-600">
                {i + 1}
              </span>
              <span className="w-4 shrink-0 select-none opacity-70">{gutter}</span>
              <span className="flex-1">{line}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
