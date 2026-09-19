"use client";

import { motion } from "framer-motion";
import { Check, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ScanStep } from "@/lib/api-types";

const STEPS: { key: ScanStep; label: string }[] = [
  { key: "checking_ssl", label: "Checking SSL" },
  { key: "fingerprinting", label: "Fingerprinting" },
  { key: "checking_cves", label: "Cross-referencing CVEs" },
  { key: "checking_exposure", label: "Checking exposure" },
  { key: "generating_report", label: "Generating report" },
];

export function ProgressStepper({ currentStep }: { currentStep: ScanStep | null }) {
  const activeIndex = (() => {
    if (!currentStep) return -1;
    if (currentStep === "completed") return STEPS.length;
    if (currentStep === "failed" || currentStep === "timeout") return -2;
    const idx = STEPS.findIndex((s) => s.key === currentStep);
    return idx === -1 ? 0 : idx;
  })();

  if (activeIndex === -2) {
    return (
      <div className="rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
        Scan failed — see findings below for details.
      </div>
    );
  }

  return (
    <ol className="flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-0">
      {STEPS.map((step, i) => {
        const done = activeIndex > i || activeIndex === STEPS.length;
        const active = activeIndex === i;
        return (
          <li key={step.key} className="flex flex-1 items-center gap-3">
            <div className="flex items-center gap-3 sm:flex-col sm:items-center sm:gap-2 sm:text-center">
              <div className="relative flex size-8 shrink-0 items-center justify-center rounded-full border">
                {active && (
                  <motion.span
                    className="absolute inset-0 rounded-full bg-accent/25"
                    animate={{ scale: [1, 1.4], opacity: [0.6, 0] }}
                    transition={{ duration: 1.4, repeat: Infinity, ease: "easeOut" }}
                  />
                )}
                <div
                  className={cn(
                    "relative flex size-8 items-center justify-center rounded-full border-2 transition-colors",
                    done
                      ? "border-accent bg-accent text-primary-foreground"
                      : active
                        ? "border-accent text-accent"
                        : "border-border text-muted-foreground",
                  )}
                >
                  {done ? (
                    <Check className="size-4" />
                  ) : active ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <span className="text-xs font-mono">{i + 1}</span>
                  )}
                </div>
              </div>
              <span
                className={cn(
                  "text-xs font-medium sm:text-[11px]",
                  done || active ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {step.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div className="hidden h-px flex-1 bg-border sm:block">
                <motion.div
                  className="h-px bg-accent"
                  initial={{ width: "0%" }}
                  animate={{ width: done ? "100%" : "0%" }}
                  transition={{ duration: 0.4 }}
                />
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
