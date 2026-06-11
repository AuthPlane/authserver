import { ReactNode } from "react";
import { C, sz, alpha } from "../tokens";

interface InfoBoxProps {
  color?: string;
  children: ReactNode;
}

export default function InfoBox({ color = C.blue, children }: InfoBoxProps) {
  return (
    <div
      style={{
        background: alpha(color, 0x12),
        border: `1px solid ${alpha(color, 0x35)}`,
        borderRadius: 6,
        padding: "10px 14px",
        fontSize: sz.base,
        color: C.textDim,
        lineHeight: 1.7,
      }}
    >
      {children}
    </div>
  );
}
