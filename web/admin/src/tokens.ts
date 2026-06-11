// Design tokens for the Authplane Admin UI.
// CSS-variable-backed for runtime theme + size switching.
// Accessibility-audited against WCAG 2.1 AA — all text colors ≥ 4.5:1.

// ---------------------------------------------------------------------------
// Color palettes
// ---------------------------------------------------------------------------

type ColorTokens = {
  bg: string; surface: string; surface2: string;
  border: string; border2: string; borderStrong: string;
  text: string; textDim: string; textMono: string;
  accent: string; danger: string; success: string;
  warn: string; blue: string; purple: string;
};

const dark: ColorTokens = {
  bg: "#0A0B0D",
  surface: "#111318",
  surface2: "#181B22",
  border: "#1E2028",
  border2: "#2A2D38",
  borderStrong: "#636A7E",
  text: "#F0F2F5",
  textDim: "#808898",
  textMono: "#9CA3AF",
  accent: "#F59E0B",
  danger: "#EF4444",
  success: "#10B981",
  warn: "#FBBF24",
  blue: "#3B82F6",
  purple: "#946CF7",
};

const light: ColorTokens = {
  bg: "#F6F8FA",
  surface: "#FFFFFF",
  surface2: "#EFF2F5",
  border: "#D0D7DE",
  border2: "#B8C0CC",
  borderStrong: "#636C76",
  text: "#1F2328",
  textDim: "#59636E",
  textMono: "#32383F",
  accent: "#8B6508",
  danger: "#CF222E",
  success: "#1A7F37",
  warn: "#9A6700",
  blue: "#0969DA",
  purple: "#8250DF",
};

const themes = { dark, light } as const;

// ---------------------------------------------------------------------------
// Font size scales
// ---------------------------------------------------------------------------

type SizeTokens = {
  xs: number; sm: number; base: number; md: number;
  lg: number; xl: number; xxl: number;
};

const sizeScales: Record<string, SizeTokens> = {
  compact:  { xs: 10, sm: 11, base: 12, md: 13, lg: 15, xl: 16, xxl: 18 },
  default:  { xs: 11, sm: 12, base: 13, md: 14, lg: 16, xl: 18, xxl: 20 },
  large:    { xs: 12, sm: 13, base: 14, md: 15, lg: 17, xl: 20, xxl: 24 },
};

// ---------------------------------------------------------------------------
// CSS variable references — these are what components import and use.
// The actual values are set on :root by applyTheme() / applySizeScale().
// ---------------------------------------------------------------------------

// Build C object: { bg: "var(--c-bg)", surface: "var(--c-surface)", ... }
const colorKeys = Object.keys(dark) as (keyof ColorTokens)[];
export const C: Record<keyof ColorTokens, string> = {} as any;
for (const k of colorKeys) {
  (C as any)[k] = `var(--c-${k})`;
}

// Build sz object: { xs: "var(--sz-xs)", ... }
// React CSSProperties fontSize accepts string | number, so "var(--sz-xs)" is valid.
const sizeKeys = Object.keys(sizeScales.default) as (keyof SizeTokens)[];
export const sz: Record<keyof SizeTokens, string> = {} as any;
for (const k of sizeKeys) {
  (sz as any)[k] = `var(--sz-${k})`;
}

// Fonts are not theme-dependent
export const fonts = {
  mono: "'JetBrains Mono', 'Fira Mono', monospace",
  sans: "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif",
} as const;

// ---------------------------------------------------------------------------
// alpha() — derive alpha-variant CSS variable from a base color variable.
// Usage: alpha(C.accent, 0x20) → "var(--c-accent-20)"
// The matching CSS variable --c-accent-20 is set by applyTheme().
// ---------------------------------------------------------------------------

const alphaLevels = [0x10, 0x12, 0x18, 0x20, 0x30, 0x35, 0x40, 0x50];

export function alpha(cssVar: string, level: number): string {
  const hex = level.toString(16).padStart(2, "0");
  return cssVar.replace(")", `-${hex})`);
}

// ---------------------------------------------------------------------------
// Theme + size application — sets CSS custom properties on :root
// ---------------------------------------------------------------------------

export type Theme = "dark" | "light";
export type SizeScale = "compact" | "default" | "large";

export function applyTheme(theme: Theme): void {
  const palette = themes[theme];
  const root = document.documentElement.style;

  for (const k of colorKeys) {
    const hex = palette[k];
    root.setProperty(`--c-${k}`, hex);
    // Pre-compute alpha variants for all commonly used levels
    for (const level of alphaLevels) {
      const a = level.toString(16).padStart(2, "0");
      root.setProperty(`--c-${k}-${a}`, `${hex}${a}`);
    }
  }

  localStorage.setItem("authplane_theme", theme);
}

export function applySizeScale(scale: SizeScale): void {
  const sizes = sizeScales[scale];
  const root = document.documentElement.style;

  for (const k of sizeKeys) {
    root.setProperty(`--sz-${k}`, `${sizes[k]}px`);
  }

  localStorage.setItem("authplane_size_scale", scale);
}

// Read current preferences from localStorage
export function getTheme(): Theme {
  return (localStorage.getItem("authplane_theme") as Theme) || "dark";
}

export function getSizeScale(): SizeScale {
  return (localStorage.getItem("authplane_size_scale") as SizeScale) || "default";
}

// Initialize — call before React mounts
export function initPreferences(): void {
  applyTheme(getTheme());
  applySizeScale(getSizeScale());
}
