import { C } from "../tokens";

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
}

export default function Toggle({ checked, onChange }: ToggleProps) {
  return (
    <div
      style={{
        width: 36,
        height: 20,
        borderRadius: 10,
        position: "relative",
        cursor: "pointer",
        background: checked ? C.success : C.border2,
        transition: "background 0.2s",
        flexShrink: 0,
      }}
      onClick={() => onChange(!checked)}
    >
      <div
        style={{
          position: "absolute",
          top: 3,
          left: checked ? 19 : 3,
          width: 14,
          height: 14,
          borderRadius: "50%",
          background: "#fff",
          transition: "left 0.2s",
          boxShadow: "0 1px 3px rgba(0,0,0,0.4)",
        }}
      />
    </div>
  );
}
