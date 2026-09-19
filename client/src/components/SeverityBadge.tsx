import type { Severity } from "../types";

const LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  NONE: "None",
};

const COLORS: Record<Severity, string> = {
  CRITICAL: "bg-severity-critical",
  HIGH: "bg-severity-high",
  MEDIUM: "bg-severity-medium",
  LOW: "bg-severity-low",
  NONE: "bg-severity-none",
};

export default function SeverityBadge({ severity, score }: { severity: Severity; score?: number | null }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-2 w-2 rounded-full ${COLORS[severity]}`} aria-hidden="true" />
      <span className="text-sm">{LABELS[severity]}</span>
      {typeof score === "number" && (
        <span className="font-mono text-xs text-console-muted">{score.toFixed(1)}</span>
      )}
    </span>
  );
}
