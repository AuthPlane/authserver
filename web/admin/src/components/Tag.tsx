import { ReactNode } from "react";
import { C, fonts, sz, alpha } from "../tokens";

interface TagProps {
  children: ReactNode;
  color?: string;
}

export default function Tag({ children, color = C.textDim }: TagProps) {
  return (
    <span
      style={{
        background: alpha(color, 0x18),
        border: `1px solid ${alpha(color, 0x40)}`,
        color,
        borderRadius: 3,
        padding: "1px 7px",
        fontSize: sz.sm,
        fontFamily: fonts.mono,
      }}
    >
      {children}
    </span>
  );
}
