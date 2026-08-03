"use client";

import { Command } from "cmdk";
import { useEffect, useState } from "react";
import { useBinarisStore } from "@/lib/store";

export function CommandPalette({
  onAsk,
  onFocusSearch,
}: {
  onAsk: (q: string) => void;
  onFocusSearch: () => void;
}) {
  const [open, setOpen] = useState(false);
  const report = useBinarisStore((s) => s.report);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[15vh] backdrop-blur-sm">
      <Command className="panel w-full max-w-xl overflow-hidden rounded-2xl">
        <Command.Input
          autoFocus
          placeholder="Search commands, ask the binary…"
          className="w-full border-b border-ink-600 bg-transparent px-4 py-3 text-sm outline-none placeholder:text-slate-500"
        />
        <Command.List className="max-h-80 overflow-auto p-2 text-sm">
          <Command.Empty className="px-3 py-6 text-slate-500">No matches</Command.Empty>
          <Command.Group heading="Ask Binaris" className="px-2 py-1 text-[11px] uppercase tracking-wider text-slate-500">
            {[
              "Summarize binary",
              "Where is networking?",
              "Show encryption",
              "What APIs are dangerous?",
              "Which function creates persistence?",
              "Why does malware probability increase?",
            ].map((q) => (
              <Command.Item
                key={q}
                value={q}
                onSelect={() => {
                  onAsk(q);
                  setOpen(false);
                }}
                className="cursor-pointer rounded-lg px-3 py-2 aria-selected:bg-ink-700"
              >
                {q}
              </Command.Item>
            ))}
          </Command.Group>
          <Command.Group heading="Workspace" className="mt-2 px-2 py-1 text-[11px] uppercase tracking-wider text-slate-500">
            <Command.Item
              onSelect={() => {
                onFocusSearch();
                setOpen(false);
              }}
              className="cursor-pointer rounded-lg px-3 py-2 aria-selected:bg-ink-700"
            >
              Focus instant search
            </Command.Item>
            <Command.Item
              onSelect={() => {
                if (report) navigator.clipboard.writeText(report.hashes.sha256);
                setOpen(false);
              }}
              className="cursor-pointer rounded-lg px-3 py-2 aria-selected:bg-ink-700"
            >
              Copy SHA-256
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}
