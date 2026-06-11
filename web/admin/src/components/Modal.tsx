import { ReactNode } from "react";
import { C, fonts, sz } from "../tokens";

interface ModalProps {
  title: string;
  titleColor?: string;
  width?: number;
  children: ReactNode;
  onClose?: () => void;
}

export default function Modal({ title, titleColor = C.danger, width = 460, children, onClose }: ModalProps) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 200,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div
        style={{
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 10,
          padding: 28,
          width,
          boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
        }}
      >
        <div
          style={{
            fontFamily: fonts.mono,
            fontSize: sz.base,
            color: titleColor,
            textTransform: "uppercase",
            letterSpacing: 1,
            marginBottom: 16,
          }}
        >
          {title}
        </div>
        {children}
      </div>
    </div>
  );
}
