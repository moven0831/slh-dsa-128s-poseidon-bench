"use client";

interface TimingStep {
  name: string;
  durationMs: number;
}

interface TimingLogProps {
  steps: TimingStep[];
  totalMs: number;
}

export function TimingLog({ steps, totalMs }: TimingLogProps) {
  const maxMs = Math.max(...steps.map((s) => s.durationMs), 1);

  return (
    <div className="font-mono text-xs space-y-1.5">
      {steps.map((step, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-zinc-500 w-48 shrink-0 truncate">
            {step.name}
          </span>
          <div className="flex-1 h-3 bg-zinc-800/60 relative overflow-hidden">
            <div
              className="h-full bg-emerald-800/60 transition-all"
              style={{ width: `${(step.durationMs / maxMs) * 100}%` }}
            />
          </div>
          <span className="text-zinc-400 w-16 text-right shrink-0">
            {step.durationMs >= 1000
              ? `${(step.durationMs / 1000).toFixed(1)}s`
              : `${step.durationMs}ms`}
          </span>
        </div>
      ))}
      <div className="border-t border-zinc-800 pt-1.5 flex justify-between text-zinc-400">
        <span>total</span>
        <span>
          {totalMs >= 1000
            ? `${(totalMs / 1000).toFixed(1)}s`
            : `${totalMs}ms`}
        </span>
      </div>
    </div>
  );
}
