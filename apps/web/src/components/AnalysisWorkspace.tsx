"use client";

import Editor from "@monaco-editor/react";
import { motion } from "framer-motion";
import {
  Activity,
  Binary,
  Bug,
  Lock,
  Network,
  Search,
  Shield,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import {
  Panel,
  PanelGroup,
  PanelResizeHandle,
} from "react-resizable-panels";
import { ChatPanel } from "@/components/ChatPanel";
import { GraphView } from "@/components/GraphView";
import { createSnapshot, listReports, listSnapshots } from "@/lib/api";
import type { AnalysisReport } from "@/lib/types";
import { formatBytes, hexAddr, riskColor } from "@/lib/utils";
import { useBinarisStore } from "@/lib/store";

export function AnalysisWorkspace({
  report,
  pendingQuestion,
  onPendingConsumed,
}: {
  report: AnalysisReport;
  pendingQuestion?: string | null;
  onPendingConsumed?: () => void;
}) {
  const selectedFunctionId = useBinarisStore((s) => s.selectedFunctionId);
  const setSelectedFunction = useBinarisStore((s) => s.setSelectedFunction);
  const token = useBinarisStore((s) => s.token);
  const [tab, setTab] = useState<
    "overview" | "functions" | "graphs" | "security" | "strings" | "network" | "reports"
  >("overview");
  const [graphKind, setGraphKind] = useState<
    "call" | "cfg" | "imports" | "dfg" | "memory" | "network"
  >("call");
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const [snapMsg, setSnapMsg] = useState<string | null>(null);

  const selected = report.functions.find((f) => f.id === selectedFunctionId) ?? report.functions[0];

  const filteredFunctions = useMemo(() => {
    const q = query.toLowerCase();
    if (!q) return report.functions;
    return report.functions.filter(
      (f) =>
        f.name.toLowerCase().includes(q) ||
        (f.suggested_name ?? "").toLowerCase().includes(q) ||
        (f.description ?? "").toLowerCase().includes(q),
    );
  }, [query, report.functions]);

  const graph =
    graphKind === "call"
      ? report.call_graph
      : graphKind === "cfg"
        ? report.cfg_summary
        : graphKind === "imports"
          ? report.import_graph
          : graphKind === "dfg"
            ? report.dfg ?? { nodes: [], edges: [] }
            : graphKind === "memory"
              ? report.memory_graph ?? { nodes: [], edges: [] }
              : report.network_graph ?? { nodes: [], edges: [] };

  return (
    <div className="flex h-[calc(100vh-4.5rem)] flex-col gap-3">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="panel grid grid-cols-2 gap-3 rounded-2xl p-4 md:grid-cols-4 xl:grid-cols-6"
      >
        <Stat icon={Binary} label="Format" value={`${report.identity.format} / ${report.identity.architecture}`} />
        <Stat icon={Shield} label="Malware" value={`${Math.round(report.malware.malware_probability * 100)}% · ${report.malware.family}`} />
        <Stat icon={Lock} label="Packer" value={report.identity.packer ?? "none"} />
        <Stat icon={Bug} label="Findings" value={`${report.security.length}`} />
        <Stat icon={Network} label="Network IOCs" value={`${report.network.length}`} />
        <Stat icon={Activity} label="Size" value={formatBytes(report.size_bytes)} />
      </motion.div>

      <div className="flex items-center gap-2">
        {(
          [
            ["overview", "Overview"],
            ["functions", "Functions"],
            ["graphs", "Graphs"],
            ["network", "Network"],
            ["security", "Security"],
            ["strings", "Strings"],
            ["reports", "Reports"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`rounded-lg px-3 py-1.5 text-sm ${
              tab === id ? "bg-accent text-ink-950" : "bg-ink-800 text-slate-300 hover:bg-ink-700"
            }`}
          >
            {label}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2 rounded-xl border border-ink-600 bg-ink-900 px-3 py-1.5">
          <Search className="h-3.5 w-3.5 text-slate-500" />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Instant search…"
            className="w-48 bg-transparent text-sm outline-none placeholder:text-slate-600"
          />
        </div>
      </div>

      <PanelGroup direction="horizontal" className="min-h-0 flex-1">
        <Panel defaultSize={62} minSize={35}>
          <div className="panel h-full overflow-auto rounded-2xl p-4">
            {tab === "overview" ? (
              <div className="space-y-4">
                <section>
                  <h3 className="font-display text-lg">Executive summary</h3>
                  <p className="mt-2 text-sm leading-relaxed text-slate-300">
                    {report.executive_summary}
                  </p>
                </section>
                <section className="grid gap-3 md:grid-cols-2">
                  <Card title="Identity">
                    <KV k="SHA-256" v={report.hashes.sha256} mono />
                    <KV k="Compiler" v={report.identity.compiler ?? "unknown"} />
                    <KV k="Language" v={report.identity.language ?? "unknown"} />
                    <KV k="Framework" v={report.identity.framework ?? "unknown"} />
                    <KV
                      k="Entry"
                      v={
                        report.identity.entry_point != null
                          ? hexAddr(report.identity.entry_point)
                          : "n/a"
                      }
                      mono
                    />
                  </Card>
                  <Card title="Malware reasoning">
                    <p className="text-sm text-slate-300">{report.malware.reasoning}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {report.malware.behaviors.map((b) => (
                        <span key={b} className="rounded-md bg-ink-700 px-2 py-1 text-[11px] text-warn">
                          {b}
                        </span>
                      ))}
                    </div>
                  </Card>
                </section>
                <Card title="Sections">
                  <div className="overflow-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="text-slate-500">
                        <tr>
                          <th className="py-1">Name</th>
                          <th>VA</th>
                          <th>Size</th>
                          <th>Entropy</th>
                          <th>Perms</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.sections.map((s) => (
                          <tr key={s.name + s.virtual_address} className="border-t border-ink-700">
                            <td className="py-1 font-mono text-accent">{s.name}</td>
                            <td className="font-mono">{hexAddr(s.virtual_address)}</td>
                            <td>{s.raw_size}</td>
                            <td className={s.entropy > 7 ? "text-warn" : ""}>{s.entropy.toFixed(2)}</td>
                            <td>{s.permissions}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </div>
            ) : null}

            {tab === "functions" ? (
              <div className="grid h-full grid-cols-1 gap-3 xl:grid-cols-[280px_1fr]">
                <div className="overflow-auto rounded-xl border border-ink-600">
                  {filteredFunctions.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => setSelectedFunction(f.id)}
                      className={`block w-full border-b border-ink-700 px-3 py-2 text-left text-xs hover:bg-ink-800 ${
                        selected?.id === f.id ? "bg-ink-800" : ""
                      }`}
                    >
                      <div className="font-mono text-accent">
                        {f.suggested_name ?? f.name}
                      </div>
                      <div className="text-slate-500">{hexAddr(f.address)}</div>
                    </button>
                  ))}
                </div>
                <div className="space-y-3">
                  {selected ? (
                    <>
                      <div>
                        <div className="font-display text-xl">
                          {selected.suggested_name ?? selected.name}
                        </div>
                        <div className="text-xs text-slate-500">
                          {hexAddr(selected.address)} · confidence{" "}
                          {Math.round(selected.confidence * 100)}%
                        </div>
                        <p className="mt-2 text-sm text-slate-300">
                          {selected.description ?? "No description yet"}
                        </p>
                      </div>
                      <div className="h-[360px] overflow-hidden rounded-xl border border-ink-600">
                        <Editor
                          height="100%"
                          defaultLanguage="asm"
                          theme="vs-dark"
                          value={selected.assembly_preview ?? "; no assembly preview"}
                          options={{
                            readOnly: true,
                            minimap: { enabled: false },
                            fontSize: 12,
                            fontFamily: "IBM Plex Mono",
                          }}
                        />
                      </div>
                    </>
                  ) : (
                    <div className="text-sm text-slate-500">No functions discovered</div>
                  )}
                </div>
              </div>
            ) : null}

            {tab === "graphs" ? (
              <div className="flex h-full flex-col gap-3">
                <div className="flex gap-2">
                  {(["call", "cfg", "imports", "dfg", "memory", "network"] as const).map((k) => (
                    <button
                      key={k}
                      onClick={() => setGraphKind(k)}
                      className={`rounded-lg px-3 py-1 text-xs uppercase tracking-wide ${
                        graphKind === k ? "bg-accent text-ink-950" : "bg-ink-800"
                      }`}
                    >
                      {k}
                    </button>
                  ))}
                </div>
                <GraphView graph={graph} />
              </div>
            ) : null}

            {tab === "security" ? (
              <div className="space-y-2">
                {report.security.length === 0 ? (
                  <div className="text-sm text-slate-500">No security findings</div>
                ) : (
                  report.security.map((f) => (
                    <div key={f.id} className="rounded-xl border border-ink-600 bg-ink-900/60 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="font-medium">{f.title}</div>
                        <div className={`text-xs uppercase ${riskColor(f.severity)}`}>
                          {f.severity}
                        </div>
                      </div>
                      <div className="mt-1 text-sm text-slate-400">{f.description}</div>
                      <div className="mt-2 text-[11px] text-slate-500">
                        {f.category}
                        {f.location ? ` · ${f.location}` : ""}
                      </div>
                    </div>
                  ))
                )}
              </div>
            ) : null}

            {tab === "strings" ? (
              <div className="overflow-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="py-1">Offset</th>
                      <th>Category</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.strings
                      .filter((s) => !query || s.value.toLowerCase().includes(query.toLowerCase()))
                      .slice(0, 300)
                      .map((s, i) => (
                        <tr key={i} className="border-t border-ink-700 align-top">
                          <td className="py-1 font-mono text-slate-500">{hexAddr(s.offset)}</td>
                          <td className="pr-3 text-accent">{s.category}</td>
                          <td className="font-mono break-all text-slate-200">{s.value}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            {tab === "network" ? (
              <div className="space-y-3">
                <Card title="Destination summary">
                  <pre className="whitespace-pre-wrap text-xs text-slate-300">
                    {JSON.stringify(report.network_intel, null, 2)}
                  </pre>
                </Card>
                <div className="h-[360px]">
                  <GraphView graph={report.network_graph ?? { nodes: [], edges: [] }} />
                </div>
              </div>
            ) : null}

            {tab === "reports" ? (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  <button
                    className="rounded-lg bg-accent px-3 py-1.5 text-sm text-ink-950"
                    onClick={async () => {
                      if (!token) return;
                      const s = await createSnapshot(token, report.id, `ui-${Date.now()}`);
                      setSnapMsg(`Snapshot saved: ${s.id}`);
                    }}
                  >
                    Save snapshot
                  </button>
                  <button
                    className="rounded-lg border border-ink-600 px-3 py-1.5 text-sm"
                    onClick={async () => {
                      if (!token) return;
                      const snaps = await listSnapshots(token, report.id);
                      setSnapMsg(`${snaps.snapshots.length} snapshots`);
                    }}
                  >
                    List snapshots
                  </button>
                  <button
                    className="rounded-lg border border-ink-600 px-3 py-1.5 text-sm"
                    onClick={async () => {
                      if (!token) return;
                      const docs = (await listReports(token, report.id)) as {
                        reports: { title: string; format: string; content: string }[];
                      };
                      const pdf = docs.reports?.find((r) => String(r.format).toLowerCase().includes("pdf"));
                      if (pdf?.content?.startsWith("data:application/pdf")) {
                        const a = document.createElement("a");
                        a.href = pdf.content;
                        a.download = `${report.filename}.pdf`;
                        a.click();
                        setSnapMsg("PDF downloaded");
                      } else {
                        setSnapMsg(`Reports available: ${docs.reports?.length ?? 0}`);
                      }
                    }}
                  >
                    Export PDF
                  </button>
                </div>
                {snapMsg ? <div className="text-sm text-accent">{snapMsg}</div> : null}
                <Card title="Decompiler backends">
                  <pre className="whitespace-pre-wrap text-xs text-slate-300">
                    {JSON.stringify(report.decomp_backends, null, 2)}
                  </pre>
                </Card>
              </div>
            ) : null}
          </div>
        </Panel>
        <PanelResizeHandle className="mx-1 w-1 rounded-full bg-ink-700 transition hover:bg-accent" />
        <Panel defaultSize={38} minSize={25}>
          <div className="panel h-full overflow-hidden rounded-2xl">
            <ChatPanel
              pendingQuestion={pendingQuestion}
              onPendingConsumed={onPendingConsumed}
            />
          </div>
        </Panel>
      </PanelGroup>
    </div>
  );
}

function Stat({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-slate-500">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className="mt-1 truncate text-sm font-medium">{value}</div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-ink-600 bg-ink-900/50 p-3">
      <div className="mb-2 text-xs uppercase tracking-wider text-slate-500">{title}</div>
      {children}
    </div>
  );
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="mb-1 grid grid-cols-[100px_1fr] gap-2 text-xs">
      <div className="text-slate-500">{k}</div>
      <div className={mono ? "truncate font-mono text-slate-200" : "truncate text-slate-200"}>
        {v}
      </div>
    </div>
  );
}
