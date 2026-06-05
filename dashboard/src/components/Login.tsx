import { useState } from "react";
import { ShieldHalf, Lock, User, Loader2, ArrowRight, Network, ScrollText, Scale } from "lucide-react";
import { login } from "@/api";

interface Props {
  onAuthenticated: (token: string) => void;
}

const DEFAULT_USER: string = (import.meta as any).env?.VITE_DEMO_USERNAME ?? "demo";
const DEFAULT_PASS: string = (import.meta as any).env?.VITE_DEMO_PASSWORD ?? "aegis-demo";

export function Login({ onAuthenticated }: Props) {
  const [username, setUsername] = useState(DEFAULT_USER);
  const [password, setPassword] = useState(DEFAULT_PASS);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await login(username, password);
      sessionStorage.setItem("aegis_token", res.token);
      onAuthenticated(res.token);
    } catch {
      setError("Authentication failed — check credentials and that the AEGIS API is running.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid h-screen grid-cols-1 bg-bg lg:grid-cols-[1.1fr_1fr]">
      {/* left — product framing */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-line p-10 lg:flex">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            maskImage: "radial-gradient(ellipse at 30% 30%, #000, transparent 75%)",
          }}
        />
        <div className="relative flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-brand/15 ring-1 ring-brand/30">
            <ShieldHalf size={20} className="text-brand" />
          </div>
          <div>
            <div className="text-[15px] font-bold tracking-wide text-ink">AEGIS</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-ink3">Security Operations Platform</div>
          </div>
        </div>

        <div className="relative max-w-md">
          <h1 className="text-[30px] font-semibold leading-tight text-ink">
            The SOC for <span className="text-brand">agent swarms</span>.
          </h1>
          <p className="mt-3 text-[14px] leading-relaxed text-ink2">
            AEGIS detects <span className="text-ink">cross-agent attack chains</span> — not isolated events. It
            correlates signals across a multi-agent system and arbitrates them into explainable, standards-mapped
            verdicts.
          </p>
          <div className="mt-7 space-y-3">
            {[
              { icon: Network, t: "Swarm-wide correlation", d: "Judge the sequence, not the call." },
              { icon: Scale, t: "Explainable verdicts", d: "Every decision shows its evidence." },
              { icon: ScrollText, t: "Hash-chained provenance", d: "Tamper-evident audit of every action." },
            ].map((f) => (
              <div key={f.t} className="flex items-start gap-3">
                <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-md border border-line bg-surface2 text-brand">
                  <f.icon size={15} />
                </span>
                <div>
                  <div className="text-[13px] font-medium text-ink">{f.t}</div>
                  <div className="text-[12px] text-ink3">{f.d}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] uppercase tracking-wider text-ink3">
          <span>Microsoft Agent Framework</span>
          <span className="text-line2">•</span>
          <span>Azure AI Foundry</span>
          <span className="text-line2">•</span>
          <span>Entra Agent ID</span>
          <span className="text-line2">•</span>
          <span>Defender for AI</span>
        </div>
      </div>

      {/* right — sign in */}
      <div className="flex items-center justify-center p-6">
        <form onSubmit={submit} className="w-full max-w-[380px]">
          <div className="mb-7 lg:hidden">
            <div className="flex items-center gap-2.5">
              <div className="grid h-9 w-9 place-items-center rounded-lg bg-brand/15 ring-1 ring-brand/30">
                <ShieldHalf size={20} className="text-brand" />
              </div>
              <div className="text-[15px] font-bold tracking-wide text-ink">AEGIS</div>
            </div>
          </div>

          <h2 className="text-[20px] font-semibold text-ink">Analyst sign-in</h2>
          <p className="mt-1 text-[13px] text-ink3">Access the operations console.</p>

          <div className="mt-6 space-y-3.5">
            <Field icon={<User size={15} />} label="Username">
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                className="w-full bg-transparent text-[14px] text-ink outline-none placeholder:text-ink3"
                placeholder="analyst"
              />
            </Field>
            <Field icon={<Lock size={15} />} label="Password">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="w-full bg-transparent text-[14px] text-ink outline-none placeholder:text-ink3"
                placeholder="••••••••"
              />
            </Field>
          </div>

          {error && (
            <div className="mt-4 rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-[12px] text-critical">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-brand py-2.5 text-[14px] font-semibold text-bg transition-colors hover:bg-brand2 disabled:opacity-60"
          >
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>Sign in <ArrowRight size={16} /></>}
          </button>

          <div className="mt-5 flex items-center gap-2 rounded-md border border-line bg-surface px-3 py-2.5 text-[11px] text-ink3">
            <span className="h-1.5 w-1.5 rounded-full bg-ok animate-pulse-dot" />
            Read-only console · demo credentials pre-filled (<span className="font-mono text-ink2">{DEFAULT_USER}</span> /{" "}
            <span className="font-mono text-ink2">{DEFAULT_PASS}</span>)
          </div>
        </form>
      </div>
    </div>
  );
}

function Field({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      <div className="mt-1 flex items-center gap-2.5 rounded-lg border border-line bg-surface px-3 py-2.5 focus-within:border-brand/60">
        <span className="text-ink3">{icon}</span>
        {children}
      </div>
    </label>
  );
}
