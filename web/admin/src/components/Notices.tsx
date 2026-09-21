import { C, fonts, sz, alpha } from "../tokens";
import type { Notice } from "../api";

// Icon geometry matches the nav icons in App.tsx (24-unit box, 1.75 stroke,
// round joins). Ico lives inside App.tsx and is not exported, and importing it
// here would close a cycle — App renders Overview, which renders this. So the
// two shapes this component needs are declared locally, the same way
// FrontingGraph owns its SVG.
const svgBase = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.75,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function SeverityIcon({ severity }: { severity: string }) {
  return (
    <svg
      // Sized in em, not px: the UI lets the operator pick a size scale
      // (compact/default/large) that drives every font size through CSS
      // variables, and a fixed icon would drift out of proportion at the
      // ends of that range. 2em tracks the title it sits next to.
      width="2em"
      height="2em"
      {...svgBase}
      // The severity is already carried by colour and by the title text; the
      // icon repeats it for anyone who cannot rely on colour alone.
      role="img"
      aria-label={severity === "warning" ? "Warning" : "Notice"}
      style={{ flexShrink: 0 }}
    >
      {severity === "warning" ? (
        <>
          <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </>
      ) : (
        <>
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </>
      )}
    </svg>
  );
}

// Notices renders the server's operator advisories — deprecations, and
// settings whose behavior is scheduled to change. The server decides which
// apply; this only draws them, so a new advisory needs no UI change.
//
// Rendered above the page content rather than in a drawer: an operator who
// never opens System should still find out before the behavior changes under
// them.

interface NoticesProps {
  notices?: Notice[];
}

function severityColor(severity: string): string {
  return severity === "warning" ? C.warn : C.blue;
}

export default function Notices({ notices }: NoticesProps) {
  if (!notices || notices.length === 0) return null;

  return (
    <div style={{ display: "grid", gap: 10, marginBottom: 20 }}>
      {notices.map(n => {
        const color = severityColor(n.severity);
        return (
          <div
            key={n.id}
            style={{
              background: alpha(color, 0x12),
              border: `1px solid ${alpha(color, 0x35)}`,
              borderRadius: 6,
              padding: "12px 16px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                fontFamily: fonts.mono,
                fontSize: sz.base,
                fontWeight: 600,
                color,
                marginBottom: 6,
              }}
            >
              <SeverityIcon severity={n.severity} />
              {n.title}
            </div>
            <div style={{ fontSize: sz.base, color: C.textDim, lineHeight: 1.7 }}>
              {n.body}
              {n.docs_url && (
                <>
                  {" "}
                  <a
                    href={n.docs_url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color, textDecoration: "underline" }}
                  >
                    Documentation
                  </a>
                </>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
