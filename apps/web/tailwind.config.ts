import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#070a0f",
          900: "#0b0f14",
          850: "#0f1520",
          800: "#141b28",
          700: "#1c2636",
          600: "#243041",
        },
        accent: {
          DEFAULT: "#22d3ee",
          dim: "#0891b2",
          glow: "#67e8f9",
        },
        warn: "#f59e0b",
        danger: "#f43f5e",
        ok: "#34d399",
      },
      fontFamily: {
        display: ["\"Syne\"", "sans-serif"],
        sans: ["\"IBM Plex Sans\"", "sans-serif"],
        mono: ["\"IBM Plex Mono\"", "monospace"],
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(36,48,65,0.9), 0 20px 50px rgba(0,0,0,0.45)",
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(34,211,238,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.05) 1px, transparent 1px)",
        aurora:
          "radial-gradient(1200px 600px at 10% -10%, rgba(34,211,238,0.18), transparent 55%), radial-gradient(900px 500px at 90% 0%, rgba(245,158,11,0.12), transparent 50%), radial-gradient(700px 400px at 50% 100%, rgba(52,211,153,0.08), transparent 60%)",
      },
    },
  },
  plugins: [],
};

export default config;
