import { ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface DrawerRowProps {
  label: string;
  value: ReactNode;
}

export default function DrawerRow({ label, value }: DrawerRowProps) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "140px 1fr",
        gap: 8,
        padding: "8px 0",
        borderBottom: `1px solid ${C.border}`,
        alignItems: "start",
      }}
    >
      <span
        style={{
          fontFamily: fonts.mono,
          fontSize: sz.xs,
          color: C.textDim,
          textTransform: "uppercase",
          letterSpacing: 0.8,
          paddingTop: 2,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontFamily: fonts.mono,
          fontSize: sz.base,
          color: C.text,
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}
