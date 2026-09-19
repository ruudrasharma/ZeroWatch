"use client";

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, Sparkles } from "lucide-react";
import type { Finding } from "@/lib/api-types";
import { SEVERITY_BG } from "@/lib/severity";
import { SeverityBadge } from "./severity-badge";
import { cn } from "@/lib/utils";

const CATEGORY_LABEL: Record<string, string> = {
  ssl: "SSL/TLS",
  headers: "Security Headers",
  cookies: "Cookies",
  cve: "CVE",
  exposure: "Exposed Path",
  subdomain: "Subdomain/DNS",
  security: "Security",
};

export function FindingCard({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const severity = finding.severity ?? "low";

  return (
    <motion.div
      layout
      className="overflow-hidden rounded-lg border bg-card"
      style={{ borderLeftWidth: 4, borderLeftColor: SEVERITY_BG[severity] }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left transition-colors hover:bg-muted/50"
        aria-expanded={open}
      >
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <SeverityBadge severity={severity} size="sm" />
          {finding.category && (
            <span className="hidden shrink-0 rounded bg-muted px-2 py-0.5 font-mono text-[10px] uppercase text-muted-foreground sm:inline-block">
              {CATEGORY_LABEL[finding.category] ?? finding.category}
            </span>
          )}
          <span className="truncate text-sm font-medium">{finding.title}</span>
        </div>
        <ChevronDown
          className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")}
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="space-y-3 border-t px-4 py-3">
              {finding.description && (
                <p className="text-sm text-muted-foreground">{finding.description}</p>
              )}
              {finding.remediation && (
                <div className="rounded-md bg-accent/5 p-3">
                  <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-accent">
                    <Sparkles className="size-3.5" />
                    AI-generated remediation — verify before acting
                  </div>
                  <p className="text-sm leading-relaxed">{finding.remediation}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
