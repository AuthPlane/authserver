import { useState, ReactNode } from "react";
import { HashRouter, Routes, Route, NavLink, Navigate } from "react-router-dom";
import { C, fonts, sz, alpha, applyTheme, applySizeScale, getTheme, getSizeScale } from "./tokens";
import type { Theme, SizeScale } from "./tokens";
import { getApiKey, clearApiKey } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Clients from "./pages/Clients";
import Users from "./pages/Users";
import AuditLog from "./pages/AuditLog";
import Resources from "./pages/Resources";
import Providers from "./pages/Providers";
import Grants from "./pages/Grants";
import Issuances from "./pages/Issuances";
import SigningKeys from "./pages/SigningKeys";
import System from "./pages/System";
import Tokens from "./pages/Tokens";
import Fronting from "./pages/Fronting";

/* ------------------------------------------------------------------ */
/*  SVG Icon system — Lucide-style, 24×24 viewBox, stroke-based       */
/* ------------------------------------------------------------------ */

const svgBase = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.75,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function Ico({ name, size = 20 }: { name: string; size?: number }) {
  return <svg width={size} height={size} {...svgBase}>{iconPaths[name]}</svg>;
}

const iconPaths: Record<string, ReactNode> = {
  gitBranch: (
    <>
      <line x1="6" y1="3" x2="6" y2="15" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </>
  ),
  grid: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </>
  ),
  monitor: (
    <>
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </>
  ),
  users: (
    <>
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </>
  ),
  lock: (
    <>
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </>
  ),
  coins: (
    <>
      <circle cx="8" cy="8" r="6" />
      <path d="M18.09 10.37A6 6 0 1 1 10.34 18" />
      <line x1="7" y1="6" x2="7.01" y2="6" />
      <line x1="9" y1="10" x2="9.01" y2="10" />
    </>
  ),
  key: (
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  ),
  clipboardCheck: (
    <>
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
      <rect x="8" y="2" width="8" height="4" rx="1" />
      <path d="m9 14 2 2 4-4" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </>
  ),
  panelClose: (
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 3v18" />
      <path d="m16 15-3-3 3-3" />
    </>
  ),
  panelOpen: (
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 3v18" />
      <path d="m14 9 3 3-3 3" />
    </>
  ),
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </>
  ),
  moon: <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z" />,
  logout: (
    <>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </>
  ),
};

/* ------------------------------------------------------------------ */
/*  Navigation items                                                   */
/* ------------------------------------------------------------------ */

interface NavItem { path: string; label: string; icon: string }

// Sidebar entries — flat list of 11 top-level surfaces post-.
// Resources / Providers / Grants / Issuances are first-class operator
// pages, NOT sub-tabs of "Tokens" or a folded "Resources" section. The
// previous "Vault" entry retired with 's endpoint removals; the
// concepts moved up to top level.
const navItems: NavItem[] = [
  { path: "/", label: "Overview", icon: "grid" },
  { path: "/clients", label: "Clients", icon: "monitor" },
  { path: "/users", label: "Users", icon: "users" },
  { path: "/resources", label: "Resources", icon: "grid" },
  { path: "/fronting", label: "Fronting", icon: "gitBranch" },
  { path: "/providers", label: "Providers", icon: "lock" },
  { path: "/grants", label: "Grants", icon: "clipboardCheck" },
  { path: "/issuances", label: "Issuances", icon: "coins" },
  { path: "/tokens", label: "Tokens", icon: "search" },
  { path: "/signing-keys", label: "Signing Keys", icon: "key" },
  { path: "/audit", label: "Audit Log", icon: "clipboardCheck" },
  { path: "/system", label: "System", icon: "settings" },
];

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const SIDEBAR_WIDE = 220;
const SIDEBAR_NARROW = 64;

/* ------------------------------------------------------------------ */
/*  Hover helper — apply/reset inline styles on mouse enter/leave      */
/* ------------------------------------------------------------------ */

function hoverStyle(
  enter: Record<string, string>,
  leave: Record<string, string>,
) {
  return {
    onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
      for (const [k, v] of Object.entries(enter))
        (e.currentTarget.style as any)[k] = v;
    },
    onMouseLeave: (e: React.MouseEvent<HTMLElement>) => {
      for (const [k, v] of Object.entries(leave))
        (e.currentTarget.style as any)[k] = v;
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Sidebar                                                            */
/* ------------------------------------------------------------------ */

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  onLogout: () => void;
  theme: Theme;
  onThemeToggle: () => void;
  sizeScale: SizeScale;
  onSizeChange: (s: SizeScale) => void;
}

function Sidebar({
  collapsed, onToggle, onLogout, theme, onThemeToggle, sizeScale, onSizeChange,
}: SidebarProps) {
  const [hoveredNav, setHoveredNav] = useState<{ path: string; top: number } | null>(null);
  const w = collapsed ? SIDEBAR_NARROW : SIDEBAR_WIDE;

  /* — shared button hover for icon-only buttons — */
  const iconBtnHover = hoverStyle(
    { background: alpha(C.text, 0x18), color: C.text },
    { background: alpha(C.text, 0x10), color: C.textDim },
  );

  return (
    <div
      style={{
        width: w,
        minWidth: w,
        background: C.surface,
        borderRight: `1px solid ${C.border}`,
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        position: "fixed",
        left: 0,
        top: 0,
        transition: "width 0.2s ease, min-width 0.2s ease",
        overflow: "hidden",
        zIndex: 50,
      }}
    >
      {/* ——— Header ——— */}
      <div
        style={{
          padding: collapsed ? "16px 0" : "16px 16px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          minHeight: 60,
          transition: "padding 0.2s ease",
        }}
      >
        {collapsed ? (
          <div
            style={{
              fontFamily: fonts.mono,
              fontSize: 18,
              fontWeight: 700,
              color: C.accent,
              width: 34,
              height: 34,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: alpha(C.accent, 0x12),
              borderRadius: 8,
            }}
          >
            A
          </div>
        ) : (
          <>
            <div>
              <div
                style={{
                  fontFamily: fonts.mono,
                  fontSize: 15,
                  fontWeight: 600,
                  color: C.accent,
                  letterSpacing: 0.5,
                }}
              >
                authplane
              </div>
              <div style={{ fontFamily: fonts.mono, fontSize: 11, color: C.textDim, marginTop: 1 }}>
                admin console
              </div>
            </div>
            <button
              onClick={onToggle}
              title="Collapse sidebar"
              style={{
                background: "transparent",
                border: "none",
                color: C.textDim,
                cursor: "pointer",
                padding: 4,
                borderRadius: 6,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
              {...hoverStyle(
                { color: C.text, background: alpha(C.text, 0x10) },
                { color: C.textDim, background: "transparent" },
              )}
            >
              <Ico name="panelClose" size={18} />
            </button>
          </>
        )}
      </div>

      {/* ——— Expand toggle (collapsed only) ——— */}
      {collapsed && (
        <button
          onClick={onToggle}
          title="Expand sidebar"
          style={{
            background: "transparent",
            border: "none",
            borderBottom: `1px solid ${C.border}`,
            color: C.textDim,
            cursor: "pointer",
            padding: "8px 0",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
          {...hoverStyle(
            { color: C.text, background: alpha(C.text, 0x10) },
            { color: C.textDim, background: "transparent" },
          )}
        >
          <Ico name="panelOpen" size={18} />
        </button>
      )}

      {/* ——— Navigation ——— */}
      <nav style={{ flex: 1, padding: "6px 0", overflowY: "auto" }}>
        {navItems.map((item) => (
          <div key={item.path} style={{ position: "relative" }}>
            <NavLink
              to={item.path}
              end={item.path === "/"}
              onMouseEnter={(e) => {
                if (collapsed) {
                  const rect = e.currentTarget.getBoundingClientRect();
                  setHoveredNav({ path: item.path, top: rect.top + rect.height / 2 });
                }
              }}
              onMouseLeave={() => setHoveredNav(null)}
              style={({ isActive }) => ({
                display: "flex",
                alignItems: "center",
                gap: collapsed ? 0 : 12,
                padding: collapsed ? "10px 0" : "9px 16px",
                justifyContent: collapsed ? "center" : "flex-start",
                fontSize: sz.base,
                fontFamily: fonts.sans,
                fontWeight: isActive ? 500 : 400,
                color: isActive ? C.accent : C.textDim,
                background: isActive ? alpha(C.accent, 0x10) : "transparent",
                borderLeft: isActive ? `3px solid ${C.accent}` : "3px solid transparent",
                textDecoration: "none",
                transition: "all 0.15s",
                cursor: "pointer",
                whiteSpace: "nowrap",
                overflow: "hidden",
              })}
            >
              <span
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 24,
                  flexShrink: 0,
                }}
              >
                <Ico name={item.icon} size={20} />
              </span>
              <span
                style={{
                  opacity: collapsed ? 0 : 1,
                  width: collapsed ? 0 : "auto",
                  overflow: "hidden",
                  transition: "opacity 0.15s ease",
                }}
              >
                {item.label}
              </span>
            </NavLink>

            {/* Tooltip when collapsed — uses fixed positioning to escape overflow:hidden */}
            {collapsed && hoveredNav?.path === item.path && (
              <div
                style={{
                  position: "fixed",
                  left: SIDEBAR_NARROW + 8,
                  top: hoveredNav.top,
                  transform: "translateY(-50%)",
                  background: C.surface,
                  border: `1px solid ${C.border2}`,
                  borderRadius: 6,
                  padding: "5px 12px",
                  fontSize: sz.sm,
                  fontFamily: fonts.sans,
                  fontWeight: 500,
                  color: C.text,
                  whiteSpace: "nowrap",
                  zIndex: 9999,
                  pointerEvents: "none",
                  boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
                }}
              >
                {item.label}
              </div>
            )}
          </div>
        ))}
      </nav>

      {/* ——— Preferences: theme + text size ——— */}
      <div
        style={{
          padding: collapsed ? "10px 8px" : "12px 16px",
          borderTop: `1px solid ${C.border}`,
          display: "flex",
          flexDirection: collapsed ? "column" : "row",
          alignItems: "center",
          gap: collapsed ? 8 : 0,
          justifyContent: collapsed ? "center" : "space-between",
          transition: "padding 0.2s ease",
        }}
      >
        {/* Theme toggle */}
        <button
          onClick={onThemeToggle}
          title={theme === "dark" ? "Switch to light" : "Switch to dark"}
          style={{
            background: alpha(C.text, 0x10),
            border: "none",
            borderRadius: 8,
            color: C.textDim,
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: collapsed ? "7px 8px" : "6px 10px",
            cursor: "pointer",
            transition: "all 0.15s",
            fontFamily: fonts.sans,
            fontSize: 12,
            fontWeight: 500,
            whiteSpace: "nowrap",
          }}
          {...iconBtnHover}
        >
          <Ico name={theme === "dark" ? "sun" : "moon"} size={16} />
          {!collapsed && <span>{theme === "dark" ? "Light" : "Dark"}</span>}
        </button>

        {/* Font size selector */}
        {collapsed ? (
          <button
            onClick={() => {
              const cycle: SizeScale[] = ["compact", "default", "large"];
              const next = cycle[(cycle.indexOf(sizeScale) + 1) % cycle.length];
              onSizeChange(next);
            }}
            title={`Text size: ${sizeScale}`}
            style={{
              background: alpha(C.text, 0x10),
              border: "none",
              borderRadius: 8,
              color: C.textDim,
              fontSize: 13,
              padding: "6px 10px",
              cursor: "pointer",
              transition: "all 0.15s",
              fontFamily: fonts.sans,
              fontWeight: 600,
            }}
            {...iconBtnHover}
          >
            {sizeScale === "compact" ? "S" : sizeScale === "default" ? "M" : "L"}
          </button>
        ) : (
          <div
            style={{
              display: "flex",
              gap: 2,
              background: alpha(C.text, 0x10),
              borderRadius: 8,
              padding: 2,
            }}
          >
            {(["compact", "default", "large"] as SizeScale[]).map((s) => (
              <button
                key={s}
                onClick={() => onSizeChange(s)}
                title={`${s.charAt(0).toUpperCase() + s.slice(1)} text`}
                style={{
                  background: sizeScale === s ? C.surface : "transparent",
                  border: "none",
                  borderRadius: 6,
                  color: sizeScale === s ? C.text : C.textDim,
                  fontSize: 12,
                  padding: "4px 10px",
                  cursor: "pointer",
                  transition: "all 0.15s",
                  fontFamily: fonts.sans,
                  fontWeight: sizeScale === s ? 600 : 500,
                  boxShadow: sizeScale === s ? "0 1px 3px rgba(0,0,0,0.1)" : "none",
                }}
              >
                {s === "compact" ? "S" : s === "default" ? "M" : "L"}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ——— Sign out ——— */}
      <div
        style={{
          padding: collapsed ? "10px 8px" : "12px 16px",
          borderTop: `1px solid ${C.border}`,
          transition: "padding 0.2s ease",
        }}
      >
        <button
          onClick={onLogout}
          title="Sign out"
          style={{
            width: "100%",
            padding: collapsed ? "8px" : "8px 12px",
            fontSize: sz.sm,
            fontFamily: fonts.sans,
            fontWeight: 500,
            color: C.textDim,
            background: "transparent",
            border: `1px solid ${C.border}`,
            borderRadius: 8,
            cursor: "pointer",
            transition: "all 0.15s",
            whiteSpace: "nowrap",
            overflow: "hidden",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 8,
          }}
          {...hoverStyle(
            { background: alpha(C.danger, 0x10), borderColor: alpha(C.danger, 0x30), color: C.danger },
            { background: "transparent", borderColor: C.border, color: C.textDim },
          )}
        >
          <Ico name="logout" size={16} />
          {!collapsed && <span>Sign out</span>}
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Layout                                                             */
/* ------------------------------------------------------------------ */

interface LayoutProps { children: ReactNode; onLogout: () => void }

function Layout({ children, onLogout }: LayoutProps) {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("authplane_sidebar") === "collapsed",
  );
  const [theme, setTheme] = useState<Theme>(getTheme);
  const [sizeScale, setSizeScale] = useState<SizeScale>(getSizeScale);

  const handleToggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    localStorage.setItem("authplane_sidebar", next ? "collapsed" : "expanded");
  };

  const handleThemeToggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  };

  const handleSizeChange = (s: SizeScale) => {
    applySizeScale(s);
    setSizeScale(s);
  };

  const sidebarWidth = collapsed ? SIDEBAR_NARROW : SIDEBAR_WIDE;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg }}>
      <Sidebar
        collapsed={collapsed}
        onToggle={handleToggle}
        onLogout={onLogout}
        theme={theme}
        onThemeToggle={handleThemeToggle}
        sizeScale={sizeScale}
        onSizeChange={handleSizeChange}
      />
      <main
        style={{
          marginLeft: sidebarWidth,
          flex: 1,
          minHeight: "100vh",
          transition: "margin-left 0.2s ease",
        }}
      >
        {children}
      </main>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  App                                                                */
/* ------------------------------------------------------------------ */

export default function App() {
  const [authed, setAuthed] = useState(!!getApiKey());

  const handleLogin = () => setAuthed(true);
  const handleLogout = () => {
    clearApiKey();
    setAuthed(false);
  };

  if (!authed) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <HashRouter>
      <Layout onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/users" element={<Users />} />
          <Route path="/resources" element={<Resources />} />
          <Route path="/fronting" element={<Fronting />} />
          <Route path="/providers" element={<Providers />} />
          <Route path="/grants" element={<Grants />} />
          <Route path="/issuances" element={<Issuances />} />
          <Route path="/tokens" element={<Tokens />} />
          <Route path="/signing-keys" element={<SigningKeys />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/system" element={<System />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </HashRouter>
  );
}
