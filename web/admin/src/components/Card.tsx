import { CSSProperties, ReactNode } from "react";
import { C } from "../tokens";

interface CardProps {
  children: ReactNode;
  style?: CSSProperties;
}

export default function Card({ children, style }: CardProps) {
  return (
    <div
      style={{
        background: C.surface,
        border: `1px solid ${C.border}`,
        borderRadius: 8,
        padding: 20,
        ...style,
      }}
    >
      {children}
    </div>
  );
}
