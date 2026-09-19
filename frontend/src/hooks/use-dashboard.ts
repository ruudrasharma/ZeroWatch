"use client";

import { useQuery } from "@tanstack/react-query";
import * as api from "@/lib/api-client";

export function useDashboardSummary() {
  return useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => api.getDashboardSummary(),
    refetchInterval: 15_000,
  });
}
