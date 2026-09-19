"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as api from "@/lib/api-client";

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { target_url: string; authorized: boolean }) =>
      api.startScan(vars.target_url, vars.authorized),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });
}

export function useScan(scanId: number | null, opts?: { poll?: boolean }) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId as number),
    enabled: scanId != null,
    refetchInterval: (query) => {
      if (!opts?.poll) return false;
      const status = query.state.data?.status;
      return status === "completed" || status === "failed" ? false : 1500;
    },
  });
}

export function useScanList(params?: { limit?: number; min_severity?: string }) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => api.listScans(params),
  });
}
