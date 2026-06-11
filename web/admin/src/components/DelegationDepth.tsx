import { C, fonts, sz } from "../tokens";
import Mono from "./Mono";

interface DelegationDepthProps {
  depth: number;
  max?: number;
}

export default function DelegationDepth({ depth, max = 4 }: DelegationDepthProps) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <Mono style={{ color: depth >= max ? C.warn : C.text }}>{depth}</Mono>
      <div style={{ display: "flex", gap: 3 }}>
        {Array.from({ length: max }).map((_, i) => (
          <div
            key={i}
            style={{
              width: 10,
              height: 6,
              borderRadius: 2,
              background: i < depth ? (depth >= max ? C.warn : C.accent) : C.border2,
              transition: "background 0.2s",
            }}
          />
        ))}
      </div>
      <span style={{ fontSize: sz.xs, color: C.textDim, fontFamily: fonts.mono }}>/ {max}</span>
    </div>
  );
}
