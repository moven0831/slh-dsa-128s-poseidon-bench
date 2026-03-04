"use client";

import type { StepStatus } from "./Stepper";

interface StepCardProps {
  title: string;
  description: string;
  status: StepStatus;
  onRun: () => void;
  disabled?: boolean;
  elapsed?: number;
  children?: React.ReactNode;
}

export function StepCard({
  title,
  description,
  status,
  onRun,
  disabled,
  elapsed,
  children,
}: StepCardProps) {
  return (
    <div
      className={`border transition-all ${
        status === "active" || status === "loading"
          ? "border-emerald-800/60 bg-zinc-900/90"
          : status === "done"
            ? "border-emerald-900/40 bg-zinc-900/60"
            : status === "error"
              ? "border-red-900/40 bg-zinc-900/60"
              : "border-zinc-800/60 bg-zinc-900/40"
      }`}
    >
      <div className="px-5 py-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="font-mono text-sm font-medium text-zinc-200">
              {title}
            </h3>
            <p className="font-mono text-xs text-zinc-500 mt-1">{description}</p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {elapsed !== undefined && (
              <span className="font-mono text-xs text-zinc-600">
                {elapsed >= 1000
                  ? `${(elapsed / 1000).toFixed(1)}s`
                  : `${elapsed}ms`}
              </span>
            )}
            <button
              onClick={onRun}
              disabled={disabled || status === "loading"}
              className={`font-mono text-xs px-3 py-1.5 border transition-all ${
                disabled || status === "loading"
                  ? "border-zinc-700 text-zinc-600 cursor-not-allowed"
                  : "border-emerald-700/60 text-emerald-400 hover:bg-emerald-950/40 hover:shadow-[0_0_12px_rgba(52,211,153,0.1)] active:scale-95"
              }`}
            >
              {status === "loading" ? (
                <span className="flex items-center gap-1.5">
                  <span className="animate-spin">⟳</span> running
                </span>
              ) : status === "done" ? (
                "re-run"
              ) : (
                "run"
              )}
            </button>
          </div>
        </div>

        {children && <div className="mt-3">{children}</div>}
      </div>
    </div>
  );
}
