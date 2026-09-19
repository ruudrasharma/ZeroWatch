"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { History as HistoryIcon, ScanSearch, Radar, ArrowUpDown } from "lucide-react";
import { useScanList } from "@/hooks/use-scans";
import { useDetectionRunList } from "@/hooks/use-detection-runs";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { riskScoreSeverity, severityWeight } from "@/lib/severity";
import type { Severity } from "@/lib/api-types";
import { cn } from "@/lib/utils";

interface Row {
  key: string;
  type: "scan" | "detection";
  href: string;
  target: string;
  date: string | null;
  severity: Severity | null;
  metric: string;
}

type TypeFilter = "all" | "scan" | "detection";
type SeverityFilter = "all" | Severity;
type SortKey = "date" | "severity";

export default function HistoryPage() {
  const { data: scans, isLoading: scansLoading } = useScanList({ limit: 100 });
  const { data: runs, isLoading: runsLoading } = useDetectionRunList();
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("date");
  const [sortDesc, setSortDesc] = useState(true);

  const isLoading = scansLoading || runsLoading;

  const rows: Row[] = useMemo(() => {
    const scanRows: Row[] = (scans ?? []).map((s) => ({
      key: `scan-${s.scan_id}`,
      type: "scan",
      href: `/recon?scan=${s.scan_id}`,
      target: s.target_url,
      date: s.completed_at ?? s.started_at,
      severity: s.risk_score != null ? riskScoreSeverity(s.risk_score) : null,
      metric: s.risk_score != null ? `risk ${s.risk_score}` : s.status,
    }));
    const runRows: Row[] = (runs ?? []).map((r) => ({
      key: `run-${r.id}`,
      type: "detection",
      href: `/anomaly?run=${r.id}`,
      target: r.held_out_category,
      date: r.completed_at ?? r.started_at,
      severity: r.highest_severity,
      metric: `${r.alert_count} alert${r.alert_count === 1 ? "" : "s"}`,
    }));
    return [...scanRows, ...runRows];
  }, [scans, runs]);

  const filtered = useMemo(() => {
    let out = rows;
    if (typeFilter !== "all") out = out.filter((r) => r.type === typeFilter);
    if (severityFilter !== "all") out = out.filter((r) => r.severity === severityFilter);
    out = [...out].sort((a, b) => {
      const dir = sortDesc ? -1 : 1;
      if (sortKey === "severity") {
        return dir * (severityWeight(a.severity) - severityWeight(b.severity));
      }
      const ad = a.date ? new Date(a.date).getTime() : 0;
      const bd = b.date ? new Date(b.date).getTime() : 0;
      return dir * (ad - bd);
    });
    return out;
  }, [rows, typeFilter, severityFilter, sortKey, sortDesc]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDesc((d) => !d);
    else {
      setSortKey(key);
      setSortDesc(true);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold">
          <HistoryIcon className="size-5 text-accent" /> History
        </h1>
        <p className="text-sm text-muted-foreground">
          All past recon scans and anomaly detection runs.
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as TypeFilter)}>
          <SelectTrigger className="w-40"><SelectValue placeholder="Type" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="scan">Recon</SelectItem>
            <SelectItem value="detection">Anomaly</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}>
          <SelectTrigger className="w-40"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="overflow-x-auto rounded-xl border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Target / category</th>
              <th className="px-4 py-3 font-medium">
                <button onClick={() => toggleSort("date")} className="flex items-center gap-1 hover:text-foreground">
                  Date <ArrowUpDown className="size-3" />
                </button>
              </th>
              <th className="px-4 py-3 font-medium">Metric</th>
              <th className="px-4 py-3 font-medium">
                <button onClick={() => toggleSort("severity")} className="flex items-center gap-1 hover:text-foreground">
                  Severity <ArrowUpDown className="size-3" />
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              [...Array(6)].map((_, i) => (
                <tr key={i} className="border-b last:border-b-0">
                  <td colSpan={5} className="px-4 py-3"><Skeleton className="h-5 w-full" /></td>
                </tr>
              ))
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                  No history matches these filters.
                </td>
              </tr>
            ) : (
              filtered.map((row, i) => (
                <motion.tr
                  key={row.key}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: Math.min(i, 10) * 0.02 }}
                  className="border-b last:border-b-0 hover:bg-muted/50"
                >
                  <td className="px-4 py-2.5">
                    <Link href={row.href} className="flex items-center gap-1.5 text-xs font-medium">
                      {row.type === "scan" ? (
                        <ScanSearch className="size-3.5 text-accent" />
                      ) : (
                        <Radar className="size-3.5 text-accent" />
                      )}
                      {row.type === "scan" ? "Recon" : "Anomaly"}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5">
                    <Link href={row.href} className={cn("block truncate font-mono text-xs")}>
                      {row.target}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {row.date ? new Date(row.date.endsWith("Z") ? row.date : `${row.date}Z`).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">{row.metric}</td>
                  <td className="px-4 py-2.5">
                    {row.severity ? <SeverityBadge severity={row.severity} size="sm" /> : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                </motion.tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
