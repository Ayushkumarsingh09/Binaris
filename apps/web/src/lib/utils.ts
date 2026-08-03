import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(2)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function riskColor(risk: string): string {
  switch (risk) {
    case "critical":
      return "text-danger";
    case "high":
      return "text-rose-300";
    case "medium":
      return "text-warn";
    case "low":
      return "text-emerald-300";
    default:
      return "text-slate-400";
  }
}

export function hexAddr(n: number): string {
  return `0x${n.toString(16)}`;
}
