import type { Severity } from "./api-types";

export const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

// Fixed bright hex values (not theme-adaptive) — used for chip/badge fills and
// chart strokes, per UI_UX_SPEC.md §2. Text-on-chip contrast is handled by
// SEVERITY_FG below rather than by darkening the chip color itself.
export const SEVERITY_BG: Record<Severity, string> = {
  low: "#4DA6FF",
  medium: "#FFD645",
  high: "#FF9F43",
  critical: "#FF4C61",
};

// Foreground text color to place on top of SEVERITY_BG (chosen per-swatch for
// contrast — the yellow "medium" swatch needs dark text, the rest read fine
// with near-white).
export const SEVERITY_FG: Record<Severity, string> = {
  low: "#04121F",
  medium: "#241D02",
  high: "#231000",
  critical: "#1A0508",
};

export const SEVERITY_DOT_CLASS: Record<Severity, string> = {
  low: "bg-low",
  medium: "bg-medium",
  high: "bg-high",
  critical: "bg-critical",
};

export function severityWeight(sev: Severity | null | undefined): number {
  if (!sev) return -1;
  return SEVERITY_ORDER.indexOf(sev);
}

export function severityFromScore(score: number): Severity | null {
  if (score < 0.5) return null;
  if (score < 0.7) return "low";
  if (score < 0.85) return "medium";
  if (score < 0.95) return "high";
  return "critical";
}

export function riskScoreSeverity(score: number): Severity {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
