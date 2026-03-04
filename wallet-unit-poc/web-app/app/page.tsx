"use client";

import { useCallback, useEffect, useReducer } from "react";
import { StatusBanner } from "@/components/StatusBanner";
import { Stepper, type StepStatus } from "@/components/Stepper";
import { StepCard } from "@/components/StepCard";
import { JsonViewer } from "@/components/JsonViewer";
import { ResultBadge } from "@/components/ResultBadge";
import { TimingLog } from "@/components/TimingLog";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface Status {
  binaryFound: boolean;
  keysExist: boolean;
  proofsExist: boolean;
  loading: boolean;
  error?: string;
}

interface TimingStep {
  name: string;
  durationMs: number;
}

interface State {
  status: Status;
  // Step 1: Parse
  parseResult: Record<string, unknown> | null;
  parseError: string | null;
  parseLoading: boolean;
  // Step 2: Build Inputs
  inputsResult: Record<string, unknown> | null;
  inputsError: string | null;
  inputsLoading: boolean;
  // Step 3: Prove
  proveResult: {
    steps: TimingStep[];
    totalMs: number;
    witnessResults: { ageAbove18: boolean; deviceKeyX: string; deviceKeyY: string };
  } | null;
  proveError: string | null;
  proveLoading: boolean;
  // Step 4: Verify
  verifyResult: {
    prepare: { valid: boolean; output: string };
    show: { valid: boolean; output: string };
    durationMs: number;
  } | null;
  verifyError: string | null;
  verifyLoading: boolean;
}

type Action =
  | { type: "SET_STATUS"; payload: Status }
  | { type: "PARSE_START" }
  | { type: "PARSE_OK"; payload: Record<string, unknown> }
  | { type: "PARSE_ERR"; payload: string }
  | { type: "INPUTS_START" }
  | { type: "INPUTS_OK"; payload: Record<string, unknown> }
  | { type: "INPUTS_ERR"; payload: string }
  | { type: "PROVE_START" }
  | { type: "PROVE_OK"; payload: State["proveResult"] }
  | { type: "PROVE_ERR"; payload: string }
  | { type: "VERIFY_START" }
  | { type: "VERIFY_OK"; payload: State["verifyResult"] }
  | { type: "VERIFY_ERR"; payload: string };

const initialState: State = {
  status: { binaryFound: false, keysExist: false, proofsExist: false, loading: true },
  parseResult: null,
  parseError: null,
  parseLoading: false,
  inputsResult: null,
  inputsError: null,
  inputsLoading: false,
  proveResult: null,
  proveError: null,
  proveLoading: false,
  verifyResult: null,
  verifyError: null,
  verifyLoading: false,
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "SET_STATUS":
      return { ...state, status: action.payload };
    case "PARSE_START":
      return { ...state, parseLoading: true, parseError: null, parseResult: null };
    case "PARSE_OK":
      return { ...state, parseLoading: false, parseResult: action.payload };
    case "PARSE_ERR":
      return { ...state, parseLoading: false, parseError: action.payload };
    case "INPUTS_START":
      return { ...state, inputsLoading: true, inputsError: null, inputsResult: null };
    case "INPUTS_OK":
      return { ...state, inputsLoading: false, inputsResult: action.payload };
    case "INPUTS_ERR":
      return { ...state, inputsLoading: false, inputsError: action.payload };
    case "PROVE_START":
      return { ...state, proveLoading: true, proveError: null, proveResult: null };
    case "PROVE_OK":
      return { ...state, proveLoading: false, proveResult: action.payload };
    case "PROVE_ERR":
      return { ...state, proveLoading: false, proveError: action.payload };
    case "VERIFY_START":
      return { ...state, verifyLoading: true, verifyError: null, verifyResult: null };
    case "VERIFY_OK":
      return { ...state, verifyLoading: false, verifyResult: action.payload };
    case "VERIFY_ERR":
      return { ...state, verifyLoading: false, verifyError: action.payload };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Test data (pre-filled, generated client-side for display only)
// ---------------------------------------------------------------------------

const TEST_DATA = {
  issuerPublicKey: {
    kty: "EC" as const,
    crv: "P-256" as const,
    // Placeholder — actual key is computed server-side via generateTestJwt()
    x: "(derived from 0123...ef)",
    y: "(derived from 0123...ef)",
  },
  devicePrivateKeyHex: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  verifierNonce: "test-nonce-12345",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function Home() {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Check backend status on mount
  useEffect(() => {
    fetch("/api/status")
      .then((r) => r.json())
      .then((data) => dispatch({ type: "SET_STATUS", payload: { ...data, loading: false } }))
      .catch((e) => dispatch({
        type: "SET_STATUS",
        payload: { binaryFound: false, keysExist: false, proofsExist: false, loading: false, error: String(e) },
      }));
  }, []);

  const stepStatus = useCallback(
    (loading: boolean, result: unknown, error: string | null): StepStatus => {
      if (loading) return "loading";
      if (error) return "error";
      if (result) return "done";
      return "idle";
    },
    [],
  );

  const steps: Array<{ label: string; status: StepStatus }> = [
    { label: "Parse", status: stepStatus(state.parseLoading, state.parseResult, state.parseError) },
    { label: "Inputs", status: stepStatus(state.inputsLoading, state.inputsResult, state.inputsError) },
    { label: "Prove", status: stepStatus(state.proveLoading, state.proveResult, state.proveError) },
    { label: "Verify", status: stepStatus(state.verifyLoading, state.verifyResult, state.verifyError) },
  ];

  // --- Step handlers ---

  async function runParse() {
    dispatch({ type: "PARSE_START" });
    try {
      // Generate test JWT server-side via the parse route
      const genRes = await fetch("/api/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ generateTest: true }),
      });
      const data = await genRes.json();
      if (!data.success) throw new Error(data.error);
      dispatch({ type: "PARSE_OK", payload: data });
    } catch (e) {
      dispatch({ type: "PARSE_ERR", payload: String(e) });
    }
  }

  async function runInputs() {
    dispatch({ type: "INPUTS_START" });
    try {
      const parseData = state.parseResult as Record<string, unknown> | null;
      if (!parseData) throw new Error("Run Parse step first");

      const res = await fetch("/api/inputs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jwt: parseData.jwt,
          disclosures: parseData.disclosures,
          issuerPublicKey: parseData.issuerPublicKey,
          devicePrivateKeyHex: parseData.devicePrivateKeyHex,
          verifierNonce: TEST_DATA.verifierNonce,
        }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      dispatch({ type: "INPUTS_OK", payload: data });
    } catch (e) {
      dispatch({ type: "INPUTS_ERR", payload: String(e) });
    }
  }

  async function runProve() {
    dispatch({ type: "PROVE_START" });
    try {
      const inputsData = state.inputsResult as Record<string, unknown> | null;
      if (!inputsData) throw new Error("Run Build Inputs step first");

      const res = await fetch("/api/prove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jwtInputs: inputsData.jwtInputs,
          showInputs: inputsData.showInputs,
        }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      dispatch({ type: "PROVE_OK", payload: data });
    } catch (e) {
      dispatch({ type: "PROVE_ERR", payload: String(e) });
    }
  }

  async function runVerify() {
    dispatch({ type: "VERIFY_START" });
    try {
      const res = await fetch("/api/verify", { method: "POST" });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      dispatch({ type: "VERIFY_OK", payload: data });
    } catch (e) {
      dispatch({ type: "VERIFY_ERR", payload: String(e) });
    }
  }

  const ready = state.status.binaryFound && state.status.keysExist;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-200">
      {/* Subtle noise overlay */}
      <div className="fixed inset-0 pointer-events-none opacity-[0.03] bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMDAiIGhlaWdodD0iMzAwIj48ZmlsdGVyIGlkPSJhIiB4PSIwIiB5PSIwIj48ZmVUdXJidWxlbmNlIHR5cGU9ImZyYWN0YWxOb2lzZSIgYmFzZUZyZXF1ZW5jeT0iLjc1IiBzdGl0Y2hUaWxlcz0ic3RpdGNoIi8+PC9maWx0ZXI+PHJlY3Qgd2lkdGg9IjMwMCIgaGVpZ2h0PSIzMDAiIGZpbHRlcj0idXJsKCNhKSIgb3BhY2l0eT0iMSIvPjwvc3ZnPg==')]" />

      <div className="relative max-w-3xl mx-auto px-4 py-12 space-y-8">
        {/* Header */}
        <header>
          <h1 className="font-mono text-lg text-emerald-400 tracking-tight">
            openac<span className="text-zinc-500">/</span>demo
          </h1>
          <p className="font-mono text-xs text-zinc-500 mt-1">
            ZK identity proof pipeline — SD-JWT → circuit inputs → Spartan2 proofs → verification
          </p>
        </header>

        {/* Status */}
        <StatusBanner {...state.status} />

        {/* Stepper */}
        <Stepper steps={steps} />

        {/* Step 1: Parse Credential */}
        <StepCard
          title="1. Parse SD-JWT Credential"
          description="Generate a test SD-JWT and parse it to extract claims, birthday index, and device binding key."
          status={steps[0].status}
          onRun={runParse}
          disabled={!ready}
        >
          {state.parseError && (
            <p className="font-mono text-xs text-red-400">{state.parseError}</p>
          )}
          {state.parseResult && (
            <JsonViewer data={state.parseResult} label="parsed credential" />
          )}
        </StepCard>

        {/* Step 2: Build Circuit Inputs */}
        <StepCard
          title="2. Build Circuit Inputs"
          description="Build JWT (Prepare) and Show circuit inputs with ECDSA signature verification and device nonce signing."
          status={steps[1].status}
          onRun={runInputs}
          disabled={!ready || !state.parseResult}
        >
          {state.inputsError && (
            <p className="font-mono text-xs text-red-400">{state.inputsError}</p>
          )}
          {state.inputsResult && (
            <JsonViewer data={state.inputsResult} label="circuit inputs" maxHeight="200px" />
          )}
        </StepCard>

        {/* Step 3: Generate Proofs */}
        <StepCard
          title="3. Generate ZK Proofs"
          description="WASM witness generation → shared blinds → Spartan2 prove + reblind for both circuits. This takes ~50s."
          status={steps[2].status}
          onRun={runProve}
          disabled={!ready || !state.inputsResult}
          elapsed={state.proveResult?.totalMs}
        >
          {state.proveError && (
            <p className="font-mono text-xs text-red-400">{state.proveError}</p>
          )}
          {state.proveResult && (
            <div className="space-y-3">
              <TimingLog steps={state.proveResult.steps} totalMs={state.proveResult.totalMs} />
              <JsonViewer
                data={state.proveResult.witnessResults}
                label="witness results"
                defaultOpen
              />
            </div>
          )}
        </StepCard>

        {/* Step 4: Verify Proofs */}
        <StepCard
          title="4. Verify Proofs"
          description="Verify both Prepare and Show proofs using the Spartan2 verifier."
          status={steps[3].status}
          onRun={runVerify}
          disabled={!ready || !state.proveResult}
          elapsed={state.verifyResult?.durationMs}
        >
          {state.verifyError && (
            <p className="font-mono text-xs text-red-400">{state.verifyError}</p>
          )}
          {state.verifyResult && (
            <ResultBadge
              valid={state.verifyResult.prepare.valid && state.verifyResult.show.valid}
              ageAbove18={state.proveResult?.witnessResults.ageAbove18}
              deviceKeyX={state.proveResult?.witnessResults.deviceKeyX}
              deviceKeyY={state.proveResult?.witnessResults.deviceKeyY}
            />
          )}
        </StepCard>

        {/* Footer */}
        <footer className="font-mono text-xs text-zinc-600 border-t border-zinc-800/60 pt-4">
          <a
            href="https://github.com/privacy-scaling-explorations/zkID"
            className="hover:text-zinc-400 transition-colors"
            target="_blank"
            rel="noopener noreferrer"
          >
            privacy-scaling-explorations/zkID
          </a>
          <span className="mx-2">·</span>
          <span>powered by openac-sdk + spartan2</span>
        </footer>
      </div>
    </div>
  );
}
