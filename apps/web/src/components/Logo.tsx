"use client";

import Image from "next/image";
import { cn } from "@/lib/utils";

export function Logo({
  size = 36,
  className,
  withWordmark = false,
}: {
  size?: number;
  className?: string;
  withWordmark?: boolean;
}) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <Image
        src="/binaris-logo.png"
        alt="Binaris"
        width={size}
        height={size}
        className="select-none drop-shadow-[0_0_18px_rgba(34,211,238,0.35)]"
        priority
      />
      {withWordmark ? (
        <div className="leading-none">
          <div className="font-display text-xl font-extrabold tracking-tight text-white">Binaris</div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-400">
            reverse intelligence
          </div>
        </div>
      ) : null}
    </div>
  );
}
