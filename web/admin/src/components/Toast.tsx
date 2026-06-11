import { useEffect, useState } from "react";
import { C, fonts, sz } from "../tokens";

interface ToastProps {
  message: string | null;
  type?: "success" | "error";
}

export default function Toast({ message, type = "success" }: ToastProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (message) {
      setVisible(true);
    } else {
      setVisible(false);
    }
  }, [message]);

  if (!visible || !message) return null;

  const bg = type === "error" ? C.danger : C.success;

  return (
    <div
      style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        background: bg,
        color: "#fff",
        padding: "10px 20px",
        borderRadius: 6,
        fontFamily: fonts.mono,
        fontSize: sz.base,
        zIndex: 300,
        boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
      }}
    >
      {type === "success" ? "\u2713 " : "\u2717 "}
      {message}
    </div>
  );
}
