"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as api from "@/lib/api-client";
import type { DetectionModel, HeldOutCategory } from "@/lib/api-types";

export function useStartDetectionRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: {
      held_out_category: HeldOutCategory;
      model: DetectionModel;
      threshold: number;
    }) => api.startDetectionRun(vars),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-runs"] });
      qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });
}

export function useDetectionRun(runId: number | null) {
  return useQuery({
    queryKey: ["detection-run", runId],
    queryFn: () => api.getDetectionRun(runId as number),
    enabled: runId != null,
  });
}

export function useDetectionRunList() {
  return useQuery({
    queryKey: ["detection-runs"],
    queryFn: () => api.listDetectionRuns(),
  });
}
