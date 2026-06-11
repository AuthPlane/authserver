import { CSSProperties } from "react";
import { C, fonts, sz } from "../tokens";

interface JsonViewProps {
  /**
   * Raw JSON value. Pass either a parsed object/array (preferred) or a string
   * containing a JSON document — strings are reparsed for pretty-printing and
   * fall back to verbatim rendering on parse error.
   */
  value: unknown;
  /** Indentation in spaces. Defaults to 2 — matches the server-side wire format. */
  indent?: number;
  style?: CSSProperties;
}

/**
 * Read-only JSON renderer with monospace styling. Used to display opaque
 * adapter-shaped JSON (provider config_data) and structured records
 * (issuance.agent_chain, dpop_jkt, etc.) without inviting accidental edits.
 *
 * Deliberately simple — no syntax highlighting, no collapsible nodes. The
 * renderable surface area is small (config blocks, ID arrays); a full
 * collapsible tree would be out of scope and would add a dependency.
 */
export default function JsonView({ value, indent = 2, style }: JsonViewProps) {
  let pretty: string;
  if (typeof value === "string") {
    try {
      pretty = JSON.stringify(JSON.parse(value), null, indent);
    } catch {
      pretty = value;
    }
  } else {
    try {
      pretty = JSON.stringify(value, null, indent);
    } catch {
      pretty = String(value);
    }
  }

  return (
    <pre
      style={{
        background: C.surface2,
        border: `1px solid ${C.border2}`,
        borderRadius: 5,
        padding: "10px 12px",
        fontFamily: fonts.mono,
        fontSize: sz.sm,
        color: C.textMono,
        margin: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        overflow: "auto",
        maxHeight: 360,
        ...style,
      }}
    >
      {pretty}
    </pre>
  );
}
