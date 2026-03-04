"use client";

interface StatusBannerProps {
  binaryFound: boolean;
  keysExist: boolean;
  proofsExist: boolean;
  loading: boolean;
  error?: string;
}

export function StatusBanner({
  binaryFound,
  keysExist,
  proofsExist,
  loading,
  error,
}: StatusBannerProps) {
  if (loading) {
    return (
      <div className="border border-zinc-700 bg-zinc-900/80 px-4 py-3 font-mono text-sm text-zinc-500">
        <span className="inline-block animate-pulse">checking backend status...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-red-900/60 bg-red-950/30 px-4 py-3 font-mono text-sm text-red-400">
        <span className="text-red-500 font-bold">ERR</span> {error}
      </div>
    );
  }

  const allGood = binaryFound && keysExist;

  return (
    <div
      className={`border px-4 py-3 font-mono text-sm ${
        allGood
          ? "border-emerald-800/60 bg-emerald-950/20 text-emerald-400"
          : "border-amber-800/60 bg-amber-950/20 text-amber-400"
      }`}
    >
      <div className="flex items-center gap-4 flex-wrap">
        <StatusDot ok={binaryFound} label="binary" />
        <StatusDot ok={keysExist} label="proving keys" />
        <StatusDot ok={proofsExist} label="cached proofs" />
        {!binaryFound && (
          <span className="text-zinc-500 text-xs ml-auto">
            run: cd ecdsa-spartan2 && cargo build --release
          </span>
        )}
        {binaryFound && !keysExist && (
          <span className="text-zinc-500 text-xs ml-auto">
            run: cargo run --release -- prepare setup && cargo run --release -- show setup
          </span>
        )}
      </div>
    </div>
  );
}

function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span
        className={`inline-block h-2 w-2 rounded-full ${
          ok ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]" : "bg-zinc-600"
        }`}
      />
      <span className={ok ? "" : "text-zinc-500"}>{label}</span>
    </span>
  );
}
