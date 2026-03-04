"use client";

interface ResultBadgeProps {
  valid: boolean;
  ageAbove18?: boolean;
  deviceKeyX?: string;
  deviceKeyY?: string;
}

export function ResultBadge({
  valid,
  ageAbove18,
  deviceKeyX,
  deviceKeyY,
}: ResultBadgeProps) {
  return (
    <div
      className={`border font-mono text-xs px-4 py-3 ${
        valid
          ? "border-emerald-800/60 bg-emerald-950/20"
          : "border-red-800/60 bg-red-950/20"
      }`}
    >
      <div className="flex items-center gap-2 mb-2">
        <span
          className={`inline-block h-2.5 w-2.5 rounded-full ${
            valid
              ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]"
              : "bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.6)]"
          }`}
        />
        <span className={valid ? "text-emerald-400 font-medium" : "text-red-400 font-medium"}>
          {valid ? "VERIFICATION PASSED" : "VERIFICATION FAILED"}
        </span>
      </div>

      {valid && (
        <div className="space-y-1 text-zinc-400 pl-4.5">
          {ageAbove18 !== undefined && (
            <div>
              ageAbove18:{" "}
              <span className={ageAbove18 ? "text-emerald-400" : "text-red-400"}>
                {String(ageAbove18)}
              </span>
            </div>
          )}
          {deviceKeyX && (
            <div className="truncate">
              deviceKey.x: <span className="text-zinc-300">{truncateHex(deviceKeyX)}</span>
            </div>
          )}
          {deviceKeyY && (
            <div className="truncate">
              deviceKey.y: <span className="text-zinc-300">{truncateHex(deviceKeyY)}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function truncateHex(s: string): string {
  if (s.length <= 20) return s;
  return s.slice(0, 10) + "..." + s.slice(-10);
}
