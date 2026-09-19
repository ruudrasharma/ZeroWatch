"use client";

import { useEffect, useRef, useState } from "react";
import { scanStreamUrl } from "@/lib/api-client";
import type { ScanStep } from "@/lib/api-types";

/**
 * Subscribes to GET /api/scans/{id}/stream (SSE) and returns the latest step
 * name. API_SPEC.md documents: checking_ssl, fingerprinting, checking_cves,
 * checking_exposure, generating_report, completed (+ failed/timeout).
 */
export function useScanProgress(scanId: number | null) {
  const [step, setStep] = useState<ScanStep | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (scanId == null) return;
    setStep(null);

    const source = new EventSource(scanStreamUrl(scanId));
    sourceRef.current = source;

    source.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as { step: ScanStep };
        setStep(data.step);
        if (["completed", "failed", "timeout"].includes(data.step)) {
          source.close();
        }
      } catch {
        // ignore malformed frame
      }
    };

    source.onerror = () => {
      source.close();
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [scanId]);

  return step;
}
