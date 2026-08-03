"use client";

import { motion } from "framer-motion";
import { Upload } from "lucide-react";
import { useCallback, useState } from "react";

export function UploadDropzone({
  busy,
  onFile,
}: {
  busy: boolean;
  onFile: (file: File) => void;
}) {
  const [drag, setDrag] = useState(false);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDrag(false);
      const file = e.dataTransfer.files?.[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
      className={`relative overflow-hidden rounded-3xl border border-dashed px-8 py-16 text-center transition ${
        drag
          ? "border-accent bg-accent/10"
          : "border-ink-600 bg-ink-900/50 hover:border-accent/50"
      }`}
    >
      <div className="pointer-events-none absolute inset-0 bg-grid bg-[size:28px_28px] opacity-40" />
      <div className="relative mx-auto flex max-w-lg flex-col items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-ink-600 bg-ink-800">
          <Upload className="h-6 w-6 text-accent" />
        </div>
        <div>
          <h2 className="font-display text-2xl font-semibold tracking-tight">
            Drop any executable
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            PE · ELF · Mach-O · APK · JAR · MSI · firmware · kernel modules · raw
          </p>
        </div>
        <label className="cursor-pointer rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-ink-950 transition hover:bg-accent-glow">
          {busy ? "Analyzing…" : "Choose file"}
          <input
            type="file"
            className="hidden"
            disabled={busy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onFile(file);
            }}
          />
        </label>
      </div>
    </motion.div>
  );
}
