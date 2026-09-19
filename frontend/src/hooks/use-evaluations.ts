"use client";

import { useQuery } from "@tanstack/react-query";
import * as api from "@/lib/api-client";

export function useEvaluations() {
  return useQuery({
    queryKey: ["evaluations"],
    queryFn: () => api.getEvaluations(),
  });
}
