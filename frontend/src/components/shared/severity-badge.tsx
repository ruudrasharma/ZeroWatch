import { AlertTriangle, AlertOctagon, AlertCircle, Info } from "lucide-react";
import type { Severity } from "@/lib/api-types";
import { SEVERITY_BG, SEVERITY_FG, SEVERITY_LABEL } from "@/lib/severity";
import { cn } from "@/lib/utils";

const ICONS: Record<Severity, typeof AlertTriangle> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
};

/**
 * Severity is always conveyed with an icon + text label alongside color, per
 * UI_UX_SPEC.md §6 (color is never the only signal).
 */
export function SeverityBadge({
  severity,
  className,
  size = "default",
}: {
  severity: Severity;
  className?: string;
  size?: "default" | "sm";
}) {
  const Icon = ICONS[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full font-medium tracking-wide uppercase",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs",
        className,
      )}
      style={{ backgroundColor: SEVERITY_BG[severity], color: SEVERITY_FG[severity] }}
    >
      <Icon className={size === "sm" ? "size-3" : "size-3.5"} strokeWidth={2.5} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
