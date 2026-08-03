"use client";

import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { AnalysisWorkspace } from "@/components/AnalysisWorkspace";
import { CommandPalette } from "@/components/CommandPalette";
import { Logo } from "@/components/Logo";
import { UploadDropzone } from "@/components/UploadDropzone";
import { listOAuthProviders, listProjects, login, oauthStartUrl, uploadBinary } from "@/lib/api";
import { useBinarisStore } from "@/lib/store";

const DEMO_PROJECT = "01900000-0000-7000-8000-000000000003";

export default function HomePage() {
  const token = useBinarisStore((s) => s.token);
  const email = useBinarisStore((s) => s.email);
  const report = useBinarisStore((s) => s.report);
  const setAuth = useBinarisStore((s) => s.setAuth);
  const setProjects = useBinarisStore((s) => s.setProjects);
  const setReport = useBinarisStore((s) => s.setReport);
  const logout = useBinarisStore((s) => s.logout);
  const activeProjectId = useBinarisStore((s) => s.activeProjectId);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null);
  const [authEmail, setAuthEmail] = useState("demo@binaris.dev");
  const [authPassword, setAuthPassword] = useState("demo-password-change-me");
  const [oauthProviders, setOauthProviders] = useState<string[]>([]);

  useEffect(() => {
    async function boot() {
      try {
        const p = await listOAuthProviders();
        setOauthProviders(p.providers ?? []);
      } catch {
        setOauthProviders([]);
      }
      if (!token) return;
      try {
        const projects = await listProjects(token);
        setProjects(projects);
      } catch {
        // token may be stale
      }
    }
    void boot();
  }, [token, setProjects]);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await login(authEmail, authPassword);
      setAuth(res.token, res.user.email, res.org_id);
      const projects = await listProjects(res.token);
      setProjects(projects);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleFile(file: File) {
    if (!token) {
      setError("Sign in first");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const projectId = activeProjectId ?? DEMO_PROJECT;
      const result = await uploadBinary(token, projectId, file);
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen px-4 pb-10 pt-4 md:px-8">
      <header className="mb-6 flex items-center justify-between gap-4">
        <Logo withWordmark size={40} />
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span className="hidden md:inline">
            <span className="kbd">Ctrl</span> + <span className="kbd">K</span> command palette
          </span>
          {token ? (
            <>
              <span className="text-slate-300">{email}</span>
              <button
                onClick={() => {
                  logout();
                  setReport(null);
                }}
                className="rounded-lg border border-ink-600 px-3 py-1.5 hover:border-accent"
              >
                Sign out
              </button>
            </>
          ) : null}
        </div>
      </header>

      {!token ? (
        <motion.section
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mx-auto grid max-w-6xl gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-center"
        >
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-accent">Binaris</p>
            <h1 className="mt-4 max-w-xl font-display text-5xl font-extrabold leading-[1.05] tracking-tight md:text-6xl">
              Reverse engineering with evidence-bound AI
            </h1>
            <p className="mt-5 max-w-lg text-base leading-relaxed text-slate-400">
              Upload PE, ELF, Mach-O, APK, firmware, and more. Binaris hashes, identifies,
              disassembles, classifies malware, detects crypto and secrets, then lets you chat
              with the binary — every claim cited.
            </p>
          </div>
          <form onSubmit={handleLogin} className="panel rounded-3xl p-6">
            <h2 className="font-display text-2xl">Sign in</h2>
            <p className="mt-1 text-sm text-slate-500">
              Demo: demo@binaris.dev / demo-password-change-me
            </p>
            <label className="mt-5 block text-xs uppercase tracking-wider text-slate-500">
              Email
              <input
                className="mt-1 w-full rounded-xl border border-ink-600 bg-ink-900 px-3 py-2 text-sm outline-none focus:border-accent"
                value={authEmail}
                onChange={(e) => setAuthEmail(e.target.value)}
              />
            </label>
            <label className="mt-3 block text-xs uppercase tracking-wider text-slate-500">
              Password
              <input
                type="password"
                className="mt-1 w-full rounded-xl border border-ink-600 bg-ink-900 px-3 py-2 text-sm outline-none focus:border-accent"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
              />
            </label>
            {error ? <p className="mt-3 text-sm text-danger">{error}</p> : null}
            <button
              disabled={busy}
              className="mt-5 w-full rounded-xl bg-accent py-2.5 text-sm font-semibold text-ink-950 disabled:opacity-60"
            >
              {busy ? "Signing in…" : "Enter workspace"}
            </button>
            {oauthProviders.length > 0 ? (
              <div className="mt-4 space-y-2">
                <div className="text-xs uppercase tracking-wider text-slate-500">SSO</div>
                {oauthProviders.map((p) => (
                  <a
                    key={p}
                    href={oauthStartUrl(p)}
                    className="block rounded-xl border border-ink-600 px-3 py-2 text-center text-sm capitalize hover:border-accent"
                  >
                    Continue with {p}
                  </a>
                ))}
              </div>
            ) : (
              <p className="mt-3 text-xs text-slate-600">
                Configure Google/GitHub/OIDC via BINARIS_OAUTH_* env vars for SSO.
              </p>
            )}
          </form>
        </motion.section>
      ) : (
        <div className="space-y-4">
          {error ? (
            <div className="rounded-xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">
              {error}
            </div>
          ) : null}
          {!report ? (
            <UploadDropzone busy={busy} onFile={handleFile} />
          ) : (
            <>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-display text-2xl">{report.filename}</div>
                  <div className="font-mono text-xs text-slate-500">{report.hashes.sha256}</div>
                </div>
                <button
                  onClick={() => setReport(null)}
                  className="rounded-xl border border-ink-600 px-3 py-2 text-sm hover:border-accent"
                >
                  New analysis
                </button>
              </div>
              <AnalysisWorkspace
                report={report}
                pendingQuestion={pendingQuestion}
                onPendingConsumed={() => setPendingQuestion(null)}
              />
            </>
          )}
        </div>
      )}

      <CommandPalette
        onAsk={(q) => setPendingQuestion(q)}
        onFocusSearch={() => {
          const el = document.querySelector<HTMLInputElement>('input[placeholder="Instant search…"]');
          el?.focus();
        }}
      />
    </main>
  );
}
