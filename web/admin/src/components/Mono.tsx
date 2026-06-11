import { CSSProperties, ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface MonoProps {
  children: ReactNode;
  style?: CSSProperties;
}

export default function Mono({ children, style }: MonoProps) {
  return (
    <span style={{ fontFamily: fonts.mono, color: C.textMono, fontSize: sz.base, ...style }}>
      {children}
    </span>
  );
}
