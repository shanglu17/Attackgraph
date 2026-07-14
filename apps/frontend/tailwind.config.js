/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Segoe UI", "Inter", "Arial", "sans-serif"],
        mono: ["Cascadia Code", "Consolas", "monospace"]
      },
      boxShadow: {
        panel: "0 12px 36px rgba(51, 78, 128, 0.10)",
        soft: "0 8px 20px rgba(60, 88, 140, 0.10)"
      }
    }
  },
  plugins: []
};
