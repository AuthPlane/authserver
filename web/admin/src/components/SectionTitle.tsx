import { ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface SectionTitleProps {
  children: ReactNode;
}

export default function SectionTitle({ children }: SectionTitleProps) {
  return (
    <div
      style={{
        fontSize: sz.xs,
        fontFamily: fonts.mono,
        textTransform: "uppercase",
        letterSpacing: 1.5,
        color: C.textDim,
        marginBottom: 14,
        paddingBottom: 8,
        borderBottom: `1px solid ${C.border}`,
      }}
    >
      {children}
    </div>
  );
}
