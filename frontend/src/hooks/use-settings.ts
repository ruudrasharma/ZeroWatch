"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as api from "@/lib/api-client";

export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: () => api.getSettings(),
  });
}

export function useSetOllamaModel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (model: string) => api.setOllamaModel(model),
    onSuccess: (data) => qc.setQueryData(["settings"], data),
  });
}

export function useResetLocalData() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.resetLocalData(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["detection-runs"] });
      qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });
}
