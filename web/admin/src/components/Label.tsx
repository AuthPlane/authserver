import { ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface LabelProps {
  children: ReactNode;
}

export default function Label({ children }: LabelProps) {
  return (
    <div
      style={{
        fontSize: sz.xs,
        fontFamily: fonts.mono,
        textTransform: "uppercase",
        letterSpacing: 1.2,
        color: C.textDim,
        marginBottom: 4,
      }}
    >
      {children}
    </div>
  );
}
