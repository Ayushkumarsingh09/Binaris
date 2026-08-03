"use client";

import { Send } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { chatWithBinary } from "@/lib/api";
import { useBinarisStore } from "@/lib/store";

type Msg = { role: "user" | "assistant"; content: string; citations?: unknown[] };

export function ChatPanel({
  pendingQuestion,
  onPendingConsumed,
}: {
  pendingQuestion?: string | null;
  onPendingConsumed?: () => void;
}) {
  const token = useBinarisStore((s) => s.token);
  const report = useBinarisStore((s) => s.report);
  const sessionId = useBinarisStore((s) => s.chatSessionId);
  const setChatSession = useBinarisStore((s) => s.setChatSession);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const askingRef = useRef(false);

  async function ask(text: string) {
    if (!token || !report || !text.trim() || busy || askingRef.current) return;
    askingRef.current = true;
    setBusy(true);
    setMessages((m) => [...m, { role: "user", content: text }]);
    setInput("");
    try {
      const res = await chatWithBinary(token, report.id, text, sessionId ?? undefined);
      setChatSession(res.session_id);
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: res.message.content,
          citations: res.message.citations,
        },
      ]);
    } catch (e) {
      setMessages((m) => [
        ...m,
        { role: "assistant", content: e instanceof Error ? e.message : "Chat failed" },
      ]);
    } finally {
      setBusy(false);
      askingRef.current = false;
      onPendingConsumed?.();
    }
  }

  useEffect(() => {
    if (pendingQuestion) {
      void ask(pendingQuestion);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingQuestion]);

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-ink-600 px-4 py-3">
        <div className="text-sm font-medium">Chat with binary</div>
        <div className="text-xs text-slate-500">Evidence-cited answers only</div>
      </div>
      <div className="flex-1 space-y-3 overflow-auto px-4 py-3">
        {messages.length === 0 ? (
          <div className="text-sm text-slate-500">
            Try “Explain main”, “Show encryption”, or “What APIs are dangerous?”
          </div>
        ) : null}
        {messages.map((m, i) => (
          <div
            key={i}
            className={`rounded-xl px-3 py-2 text-sm ${
              m.role === "user"
                ? "ml-8 bg-accent/15 text-accent-glow"
                : "mr-4 whitespace-pre-wrap bg-ink-800 text-slate-200"
            }`}
          >
            {m.content}
            {m.citations && (m.citations as unknown[]).length > 0 ? (
              <div className="mt-2 border-t border-ink-600 pt-2 text-[11px] text-slate-500">
                {(m.citations as { note?: string; kind?: string }[])
                  .slice(0, 6)
                  .map((c, idx) => (
                    <div key={idx}>• {c.note ?? c.kind ?? "evidence"}</div>
                  ))}
              </div>
            ) : null}
          </div>
        ))}
      </div>
      <form
        className="flex gap-2 border-t border-ink-600 p-3"
        onSubmit={(e) => {
          e.preventDefault();
          void ask(input);
        }}
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about this binary…"
          className="flex-1 rounded-xl border border-ink-600 bg-ink-900 px-3 py-2 text-sm outline-none focus:border-accent"
        />
        <button
          type="submit"
          disabled={busy}
          className="rounded-xl bg-accent px-3 text-ink-950 disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
}
