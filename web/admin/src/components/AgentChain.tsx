import { C, fonts, sz, alpha } from "../tokens";

interface AgentChainProps {
  chain: string[];
  onClientClick?: (id: string) => void;
}

export default function AgentChain({ chain, onClientClick }: AgentChainProps) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
      {chain.map((id, i) => (
        <span key={id} style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <span
            onClick={() => onClientClick?.(id)}
            style={{
              background: alpha(C.purple, 0x18),
              border: `1px solid ${alpha(C.purple, 0x40)}`,
              color: C.purple,
              borderRadius: 3,
              padding: "1px 8px",
              fontSize: sz.sm,
              fontFamily: fonts.mono,
              cursor: onClientClick ? "pointer" : "default",
              transition: "background 0.15s",
            }}
            onMouseEnter={(e) => {
              if (onClientClick) e.currentTarget.style.background = alpha(C.purple, 0x30);
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = alpha(C.purple, 0x18);
            }}
          >
            {id}
          </span>
          {i < chain.length - 1 && (
            <span style={{ color: C.textDim, fontSize: sz.xs }}>{"\u2192"}</span>
          )}
        </span>
      ))}
    </div>
  );
}
