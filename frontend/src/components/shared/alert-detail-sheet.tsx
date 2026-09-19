"use client";

import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { ShapBarChart } from "./shap-bar-chart";
import { SeverityBadge } from "./severity-badge";
import type { AnomalyAlert } from "@/lib/api-types";
import { Sparkles, ShieldOff, ShieldCheck } from "lucide-react";

export function AlertDetailSheet({
  alert,
  open,
  onOpenChange,
}: {
  alert: AnomalyAlert | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        {alert && (
          <>
            <SheetHeader>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={alert.severity} />
                <SheetTitle className="font-mono">{alert.flow_id}</SheetTitle>
              </div>
              <SheetDescription>
                Anomaly detection alert detail — SHAP-based explainability
              </SheetDescription>
            </SheetHeader>

            <div className="mt-6 space-y-6">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border bg-card p-3">
                  <p className="text-xs text-muted-foreground">Model confidence</p>
                  <p className="mt-1 font-mono text-2xl font-bold tabular-nums">
                    {(alert.anomaly_score * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="rounded-lg border bg-card p-3">
                  <p className="text-xs text-muted-foreground">Severity</p>
                  <p className="mt-1 text-sm font-medium capitalize">{alert.severity}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 p-3">
                  <ShieldOff className="size-4 text-muted-foreground" />
                  <div>
                    <p className="text-xs text-muted-foreground">Signature match</p>
                    <p className="font-mono text-xs">
                      {alert.signature_match && alert.signature_match !== "none"
                        ? alert.signature_match
                        : "none"}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/5 p-3">
                  <ShieldCheck className="size-4 text-accent" />
                  <div>
                    <p className="text-xs text-muted-foreground">AI verdict</p>
                    <p className="text-xs font-medium text-accent">anomalous</p>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Top contributing features (SHAP)
                </h4>
                <ShapBarChart shapValues={alert.shap_values} />
              </div>

              <div className="rounded-md bg-accent/5 p-3">
                <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-accent">
                  <Sparkles className="size-3.5" />
                  AI-generated explanation — verify before acting
                </div>
                <p className="text-sm leading-relaxed">{alert.explanation}</p>
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
