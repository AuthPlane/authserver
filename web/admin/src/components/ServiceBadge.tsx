import { C, fonts, sz } from "../tokens";

const serviceLabels: Record<string, string> = {
  github: "GitHub",
  linear: "Linear",
  slack: "Slack",
};

interface ServiceBadgeProps {
  service: string;
}

export default function ServiceBadge({ service }: ServiceBadgeProps) {
  return (
    <span
      style={{
        background: C.surface2,
        border: `1px solid ${C.border2}`,
        borderRadius: 3,
        padding: "2px 8px",
        fontSize: sz.sm,
        fontFamily: fonts.mono,
        color: C.textMono,
        letterSpacing: 0.5,
      }}
    >
      {serviceLabels[service] || service}
    </span>
  );
}
