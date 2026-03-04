"use client";

export type StepStatus = "idle" | "active" | "loading" | "done" | "error";

interface StepperProps {
  steps: Array<{ label: string; status: StepStatus }>;
}

export function Stepper({ steps }: StepperProps) {
  return (
    <div className="flex items-center gap-0 font-mono text-xs overflow-x-auto">
      {steps.map((step, i) => (
        <div key={i} className="flex items-center">
          {i > 0 && (
            <div
              className={`w-8 h-px mx-1 ${
                step.status === "done" || step.status === "active" || step.status === "loading"
                  ? "bg-emerald-600"
                  : "bg-zinc-700"
              }`}
            />
          )}
          <div
            className={`flex items-center gap-1.5 px-3 py-1.5 border transition-all ${statusStyles(step.status)}`}
          >
            <StepIndicator status={step.status} index={i} />
            <span>{step.label}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function statusStyles(status: StepStatus): string {
  switch (status) {
    case "done":
      return "border-emerald-800/60 bg-emerald-950/30 text-emerald-400";
    case "active":
      return "border-emerald-700/80 bg-emerald-950/40 text-emerald-300 shadow-[0_0_12px_rgba(52,211,153,0.1)]";
    case "loading":
      return "border-amber-700/60 bg-amber-950/20 text-amber-400";
    case "error":
      return "border-red-800/60 bg-red-950/20 text-red-400";
    default:
      return "border-zinc-700/60 bg-zinc-900/40 text-zinc-500";
  }
}

function StepIndicator({ status, index }: { status: StepStatus; index: number }) {
  if (status === "loading") {
    return <span className="animate-spin text-amber-400">⟳</span>;
  }
  if (status === "done") {
    return <span className="text-emerald-400">✓</span>;
  }
  if (status === "error") {
    return <span className="text-red-400">✗</span>;
  }
  return <span className="text-zinc-600">{index + 1}</span>;
}
