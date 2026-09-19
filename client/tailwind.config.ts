import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        console: {
          bg: "#10131A",      // page background
          panel: "#181C24",   // raised surfaces / table zebra
          panel2: "#1E232C",  // nested surfaces / hover
          border: "#282E38",  // hairline borders
          text: "#DDE2E8",    // primary text
          muted: "#828C9A",   // secondary text
          signal: "#FFB454",  // single sparing accent — active states, primary actions
        },
        severity: {
          critical: "#E5484D",
          high: "#F0883E",
          medium: "#E8C547",
          low: "#5B9BD5",
          none: "#4A515C",
        },
      },
      fontFamily: {
        sans: ["'IBM Plex Sans'", "system-ui", "sans-serif"],
        mono: ["'IBM Plex Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        xs: ["0.75rem", { lineHeight: "1.1rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.9375rem", { lineHeight: "1.5rem" }],
        lg: ["1.125rem", { lineHeight: "1.6rem" }],
        xl: ["1.375rem", { lineHeight: "1.75rem" }],
        "2xl": ["1.75rem", { lineHeight: "2.1rem" }],
      },
    },
  },
  plugins: [],
} satisfies Config;
