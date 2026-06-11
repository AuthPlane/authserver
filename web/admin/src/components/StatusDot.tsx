import { C } from "../tokens";

const statusColors: Record<string, string> = {
  active: C.success,
  healthy: C.success,
  connected: C.success,
  enabled: C.success,
  disabled: C.textDim,
  suspended: C.danger,
  error: C.danger,
  rejected: C.danger,
  warning: C.warn,
};

interface StatusDotProps {
  status: string;
}

export default function StatusDot({ status }: StatusDotProps) {
  const color = statusColors[status] || C.textDim;
  return (
    <span
      style={{
        display: "inline-block",
        width: 7,
        height: 7,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
        flexShrink: 0,
      }}
    />
  );
}
