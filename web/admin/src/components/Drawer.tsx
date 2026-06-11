import { ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface DrawerProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  onClose: () => void;
  width?: number;
}

export default function Drawer({ title, subtitle, children, onClose, width = 480 }: DrawerProps) {
  return (
    <>
      <div
        style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.3)", zIndex: 99 }}
        onClick={onClose}
      />
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width,
          background: C.surface,
          borderLeft: `1px solid ${C.border}`,
          overflowY: "auto",
          zIndex: 100,
          boxShadow: "-20px 0 60px rgba(0,0,0,0.5)",
        }}
      >
        <div
          style={{
            padding: "16px 20px",
            borderBottom: `1px solid ${C.border}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
          }}
        >
          <div>
            <div
              style={{
                fontFamily: fonts.mono,
                fontSize: sz.sm,
                textTransform: "uppercase",
                letterSpacing: 1.2,
                color: C.textDim,
              }}
            >
              {title}
            </div>
            {subtitle && (
              <div style={{ fontSize: sz.base, color: C.text, marginTop: 3 }}>{subtitle}</div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: "none",
              border: "none",
              color: C.textDim,
              cursor: "pointer",
              fontSize: sz.xxl,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>
        <div style={{ padding: 20 }}>{children}</div>
      </div>
    </>
  );
}
