import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: [
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './src/presentation/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        aegis: {
          bg: '#0B1120',
          surface: '#111827',
          elevated: '#1E293B',
          text: '#F8FAFC',
          muted: '#94A3B8',
          amber: '#F59E0B',
          amberLight: '#FBBF24',
          violet: '#8B5CF6',
          emerald: '#10B981',
          crimson: '#EF4444',
          cyan: '#06B6D4',
        },
      },
      fontFamily: {
        mono: ['"Be Vietnam Pro"', 'system-ui', '-apple-system', 'sans-serif'],
        sans: ['"Be Vietnam Pro"', 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};

export default config;
