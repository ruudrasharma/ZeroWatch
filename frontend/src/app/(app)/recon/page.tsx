"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { Download, Loader2, ScanSearch, ShieldCheck, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { useStartScan, useScan } from "@/hooks/use-scans";
import { useScanProgress } from "@/hooks/use-scan-progress";
import { ProgressStepper } from "@/components/shared/progress-stepper";
import { RiskGauge } from "@/components/shared/risk-gauge";
import { FindingCard } from "@/components/shared/finding-card";
import { staggerContainer, staggerItem } from "@/components/shared/page-transition";
import { scanPdfUrl } from "@/lib/api-client";
import { ApiError } from "@/lib/api-client";
import { SEVERITY_ORDER } from "@/lib/severity";
import type { Severity } from "@/lib/api-types";

function isValidUrl(value: string) {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function ReconPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanIdParam = searchParams.get("scan");
  const scanId = scanIdParam ? Number(scanIdParam) : null;

  if (scanId != null && !Number.isNaN(scanId)) {
    return <ScanResults scanId={scanId} onReset={() => router.push("/recon")} />;
  }
  return <ScanForm onStarted={(id) => router.push(`/recon?scan=${id}`)} />;
}

function ScanForm({ onStarted }: { onStarted: (scanId: number) => void }) {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [touched, setTouched] = useState(false);
  const mutation = useStartScan();

  const urlValid = isValidUrl(url);
  const canSubmit = urlValid && authorized && !mutation.isPending;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;
    mutation.mutate(
      { target_url: url, authorized },
      { onSuccess: (data) => onStarted(data.scan_id) },
    );
  }

  return (
    <div className="mx-auto max-w-xl">
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <div className="mb-6 flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-accent/10 text-accent">
            <ScanSearch className="size-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold">Recon Engine</h1>
            <p className="text-sm text-muted-foreground">
              Scan a website for known vulnerabilities and misconfigurations.
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5 rounded-xl border bg-card p-6">
          <div className="space-y-1.5">
            <label htmlFor="target_url" className="text-sm font-medium">
              Target URL
            </label>
            <Input
              id="target_url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono"
              autoComplete="off"
            />
            {touched && !urlValid && (
              <p className="text-xs text-critical">
                Enter a valid http:// or https:// URL.
              </p>
            )}
          </div>

          <label className="flex items-start gap-3 rounded-lg border border-border bg-muted/30 p-3 text-sm">
            <Checkbox
              checked={authorized}
              onCheckedChange={(v) => setAuthorized(v === true)}
              className="mt-0.5"
            />
            <span>
              I own this domain or have explicit authorization to test it. Active
              checks are passive-only (equivalent to what a browser reveals) —
              see <span className="font-medium">SECURITY.md</span> for details.
            </span>
          </label>

          {mutation.isError && (
            <p className="text-sm text-critical">
              {mutation.error instanceof ApiError
                ? mutation.error.message
                : "Failed to start scan."}
            </p>
          )}

          <Button type="submit" disabled={!canSubmit} className="w-full gap-2">
            {mutation.isPending ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <ShieldCheck className="size-4" />
            )}
            Start Scan
          </Button>
        </form>
      </motion.div>
    </div>
  );
}

function ScanResults({ scanId, onReset }: { scanId: number; onReset: () => void }) {
  const { data: scan, isLoading } = useScan(scanId, { poll: true });
  const liveStep = useScanProgress(scanId);
  const inProgress = scan && (scan.status === "pending" || scan.status === "running");

  if (isLoading || !scan) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 rounded-xl" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Recon Report</h1>
          <p className="truncate font-mono text-sm text-muted-foreground">{scan.target_url}</p>
        </div>
        <div className="flex gap-2">
          {scan.status === "completed" && (
            <a href={scanPdfUrl(scanId)} target="_blank" rel="noreferrer">
              <Button variant="outline" size="sm" className="gap-1.5">
                <Download className="size-3.5" /> Export PDF
              </Button>
            </a>
          )}
          <Button variant="ghost" size="sm" className="gap-1.5" onClick={onReset}>
            <RotateCcw className="size-3.5" /> New scan
          </Button>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {inProgress ? (
          <motion.div
            key="progress"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border bg-card p-6"
          >
            <ProgressStepper currentStep={liveStep ?? scan.status} />
          </motion.div>
        ) : (
          <motion.div
            key="results"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            {scan.status === "completed" && scan.risk_score != null && (
              <div className="flex justify-center">
                <RiskGauge score={scan.risk_score} />
              </div>
            )}
            {scan.status === "failed" && (
              <div className="rounded-lg border border-critical/30 bg-critical/10 p-4 text-sm text-critical">
                Scan failed to complete. See findings below.
              </div>
            )}

            <motion.div
              variants={staggerContainer}
              initial="hidden"
              animate="show"
              className="space-y-3"
            >
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                Findings ({scan.findings.length})
              </h2>
              {scan.findings.length === 0 ? (
                <p className="text-sm text-muted-foreground">No findings recorded.</p>
              ) : (
                [...scan.findings]
                  .sort((a, b) => {
                    const wa = SEVERITY_ORDER.indexOf((a.severity as Severity) ?? "low");
                    const wb = SEVERITY_ORDER.indexOf((b.severity as Severity) ?? "low");
                    return wb - wa;
                  })
                  .map((finding) => (
                    <motion.div key={finding.id} variants={staggerItem}>
                      <FindingCard finding={finding} />
                    </motion.div>
                  ))
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function ReconPage() {
  return (
    <Suspense fallback={<Skeleton className="h-40 rounded-xl" />}>
      <ReconPageInner />
    </Suspense>
  );
}
