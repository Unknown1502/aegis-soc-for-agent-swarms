/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Enterprise SOC palette (Defender XDR / Sentinel lineage):
        // flat, desaturated surfaces, one calm blue accent, semantic threat hues.
        bg: "#0a0d13",
        surface: "#0f131b",
        surface2: "#141923",
        surface3: "#1a2030",
        line: "#212836",
        line2: "#2b3445",
        ink: "#e6e9ef",
        ink2: "#aab3c2",
        ink3: "#6f7a8c",
        brand: "#3b9eff",
        brand2: "#2b7fe0",
        // severities
        critical: "#f85149",
        high: "#f0883e",
        medium: "#d29922",
        low: "#3fb950",
        info: "#58a6ff",
        ok: "#3fb950",
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "Consolas", "monospace"],
        sans: ["'Inter'", "Segoe UI", "system-ui", "sans-serif"],
      },
      fontSize: {
        "2xs": ["10px", "14px"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.4)",
        pop: "0 8px 28px -8px rgba(0,0,0,0.7)",
      },
      keyframes: {
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-dot": {
          "0%": { boxShadow: "0 0 0 0 rgba(63,185,80,0.5)" },
          "70%": { boxShadow: "0 0 0 5px rgba(63,185,80,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(63,185,80,0)" },
        },
        "dash": { to: { strokeDashoffset: "-16" } },
      },
      animation: {
        "fade-in": "fade-in .25s ease both",
        "pulse-dot": "pulse-dot 2s ease-out infinite",
        "dash": "dash 0.6s linear infinite",
      },
    },
  },
  plugins: [],
};
