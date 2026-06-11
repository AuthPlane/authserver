import { ReactNode } from "react";
import { C, fonts, alpha } from "../tokens";

interface BtnProps {
  children: ReactNode;
  onClick?: () => void;
  danger?: boolean;
  secondary?: boolean;
  small?: boolean;
  disabled?: boolean;
  full?: boolean;
}

export default function Btn({ children, onClick, danger, secondary, small, disabled, full }: BtnProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding: small ? "4px 12px" : "7px 16px",
        fontSize: small ? 12 : 13,
        fontFamily: fonts.mono,
        fontWeight: 500,
        width: full ? "100%" : "auto",
        background: danger ? alpha(C.danger, 0x20) : secondary ? "transparent" : alpha(C.accent, 0x20),
        color: danger ? C.danger : secondary ? C.textDim : C.accent,
        border: `1px solid ${danger ? alpha(C.danger, 0x50) : secondary ? C.border2 : alpha(C.accent, 0x50)}`,
        borderRadius: 5,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
        transition: "all 0.15s",
        letterSpacing: 0.3,
      }}
    >
      {children}
    </button>
  );
}
