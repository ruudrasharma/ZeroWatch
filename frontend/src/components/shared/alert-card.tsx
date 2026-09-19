"use client";

import { motion } from "framer-motion";
import { ShieldAlert } from "lucide-react";
import type { AnomalyAlert } from "@/lib/api-types";
import { SEVERITY_BG } from "@/lib/severity";
import { SeverityBadge } from "./severity-badge";
import { cn } from "@/lib/utils";

export function AlertCard({
  alert,
  onClick,
  className,
}: {
  alert: AnomalyAlert;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <motion.button
      type="button"
      onClick={onClick}
      layout
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "w-full rounded-lg border bg-card p-3 text-left transition-colors hover:bg-muted/50",
        className,
      )}
      style={{ borderLeftWidth: 3, borderLeftColor: SEVERITY_BG[alert.severity] }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-critical" />
          <span className="font-mono text-xs text-muted-foreground">{alert.flow_id}</span>
        </div>
        <SeverityBadge severity={alert.severity} size="sm" />
      </div>
      <div className="mt-2 flex items-center justify-between text-xs">
        <span className="font-mono tabular-nums text-foreground">
          score {alert.anomaly_score.toFixed(3)}
        </span>
        <span className="text-muted-foreground">
          sig: {alert.signature_match && alert.signature_match !== "none" ? alert.signature_match : "none"}
        </span>
      </div>
    </motion.button>
  );
}
