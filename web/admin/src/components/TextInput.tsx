import { CSSProperties } from "react";
import { C, fonts, sz } from "../tokens";

interface TextInputProps {
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  rows?: number;
  style?: CSSProperties;
}

export default function TextInput({ placeholder, value, onChange, type = "text", rows, style }: TextInputProps) {
  const base: CSSProperties = {
    background: C.surface2,
    border: `1px solid ${C.border2}`,
    borderRadius: 5,
    padding: rows ? "8px 12px" : "6px 12px",
    color: C.text,
    fontSize: sz.base,
    fontFamily: fonts.mono,
    outline: "none",
    width: "100%",
    boxSizing: "border-box",
    ...style,
  };

  if (rows) {
    return (
      <textarea
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={rows}
        style={{ ...base, resize: "vertical" }}
      />
    );
  }

  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={base}
    />
  );
}
