import { useState } from "react";
import { C, fonts, sz } from "../tokens";
import IssuedTab from "./tokens/IssuedTab";
import InspectorTab from "./tokens/InspectorTab";

const tabs = [
  { id: "issued", label: "Issued" },
  { id: "inspector", label: "Inspector" },
] as const;

type TabId = (typeof tabs)[number]["id"];

export default function Tokens() {
  const [tab, setTab] = useState<TabId>("issued");

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: sz.xl, fontWeight: 600, fontFamily: fonts.mono }}>Tokens</div>
        <div style={{ fontSize: sz.base, color: C.textDim, marginTop: 2 }}>
          Issued tokens · JWT inspector. Forensic queries by user / client / JTI live on the Issuances page.
        </div>
      </div>

      <div style={{ display: "flex", gap: 2, marginBottom: 24, borderBottom: `1px solid ${C.border}` }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: "8px 18px",
              background: "none",
              border: "none",
              borderBottom: `2px solid ${tab === t.id ? C.accent : "transparent"}`,
              color: tab === t.id ? C.accent : C.textDim,
              cursor: "pointer",
              fontFamily: fonts.mono,
              fontSize: sz.base,
              marginBottom: -1,
              transition: "all 0.15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "issued" && <IssuedTab />}
      {tab === "inspector" && <InspectorTab />}
    </div>
  );
}
