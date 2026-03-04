"use client";

import { useState } from "react";

interface JsonViewerProps {
  data: unknown;
  label?: string;
  defaultOpen?: boolean;
  maxHeight?: string;
}

export function JsonViewer({
  data,
  label,
  defaultOpen = false,
  maxHeight = "300px",
}: JsonViewerProps) {
  const [open, setOpen] = useState(defaultOpen);

  const formatted = JSON.stringify(
    data,
    (_key, value) =>
      typeof value === "bigint" ? value.toString() + "n" : value,
    2,
  );

  return (
    <div className="border border-zinc-800/60 bg-black/40">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-3 py-2 flex items-center gap-2 font-mono text-xs text-zinc-400 hover:text-zinc-300 transition-colors"
      >
        <span
          className={`transition-transform ${open ? "rotate-90" : ""}`}
        >
          ▸
        </span>
        {label ?? "output"}
        <span className="text-zinc-600 ml-auto">
          {open ? "collapse" : "expand"}
        </span>
      </button>
      {open && (
        <pre
          className="px-3 pb-3 font-mono text-xs text-emerald-300/80 overflow-auto whitespace-pre-wrap break-all"
          style={{ maxHeight }}
        >
          {formatted}
        </pre>
      )}
    </div>
  );
}
