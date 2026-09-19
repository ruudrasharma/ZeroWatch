"use client";

import { motion } from "framer-motion";
import type { WsFlowEvent } from "@/lib/api-types";
import { severityFromScore, SEVERITY_BG } from "@/lib/severity";

export function LiveTrafficRow({ flow }: { flow: WsFlowEvent }) {
  const severity = severityFromScore(flow.anomaly_score);
  const barColor = severity ? SEVERITY_BG[severity] : "var(--accent)";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.25 }}
      className="grid grid-cols-[1fr_1fr_auto_5rem] items-center gap-2 border-b border-border/60 px-3 py-1.5 font-mono text-xs last:border-b-0"
    >
      <span className="truncate text-muted-foreground">
        {flow.src_ip} <span className="text-muted-foreground/50">→</span> {flow.dst_ip}
      </span>
      <span className="truncate text-muted-foreground/70">{flow.flow_id}</span>
      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
        {flow.protocol}
      </span>
      <div className="flex items-center gap-1.5">
        <div className="h-1.5 w-10 overflow-hidden rounded-full bg-muted">
          <motion.div
            className="h-full rounded-full"
            style={{ backgroundColor: barColor }}
            initial={{ width: 0 }}
            animate={{ width: `${Math.min(flow.anomaly_score, 1) * 100}%` }}
            transition={{ duration: 0.4, ease: "easeOut" }}
          />
        </div>
        <span className="tabular-nums" style={{ color: severity ? barColor : undefined }}>
          {flow.anomaly_score.toFixed(2)}
        </span>
      </div>
    </motion.div>
  );
}
