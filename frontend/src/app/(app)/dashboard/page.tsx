"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { Activity, Gauge, ShieldAlert, ScanSearch, Radar, ArrowRight } from "lucide-react";
import { useDashboardSummary } from "@/hooks/use-dashboard";
import { StatCard } from "@/components/shared/stat-card";
import { Skeleton } from "@/components/ui/skeleton";
import { staggerContainer, staggerItem } from "@/components/shared/page-transition";

function timeAgo(iso: string | null) {
  if (!iso) return "";
  const then = new Date(iso.endsWith("Z") ? iso : `${iso}Z`).getTime();
  const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export default function DashboardPage() {
  const { data, isLoading } = useDashboardSummary();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Aggregate stats across your Recon scans and Zero-Day detection runs.
        </p>
      </div>

      <motion.div
        variants={staggerContainer}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 gap-4 sm:grid-cols-3"
      >
        {isLoading || !data ? (
          <>
            <Skeleton className="h-28 rounded-xl" />
            <Skeleton className="h-28 rounded-xl" />
            <Skeleton className="h-28 rounded-xl" />
          </>
        ) : (
          <>
            <motion.div variants={staggerItem}>
              <StatCard label="Total Scans" value={data.total_scans} icon={ScanSearch} accent />
            </motion.div>
            <motion.div variants={staggerItem}>
              <StatCard
                label="Avg Risk Score"
                value={data.avg_risk_score ?? 0}
                icon={Gauge}
                decimals={data.avg_risk_score != null ? 1 : 0}
              />
            </motion.div>
            <motion.div variants={staggerItem}>
              <StatCard
                label="Anomalies Flagged (7d)"
                value={data.anomalies_flagged_7d}
                icon={ShieldAlert}
              />
            </motion.div>
          </>
        )}
      </motion.div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <LaunchCard
          href="/recon"
          icon={ScanSearch}
          title="Recon Engine"
          description="Scan a website for known vulnerabilities, misconfigurations, and exposed paths."
        />
        <LaunchCard
          href="/anomaly"
          icon={Radar}
          title="Zero-Day Engine"
          description="Replay live traffic and watch AI flag anomalies signatures would miss."
        />
      </div>

      <div>
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <Activity className="size-4" /> Recent activity
        </h2>
        <div className="divide-y divide-border rounded-xl border bg-card">
          {isLoading || !data ? (
            <div className="space-y-0">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center gap-3 p-4">
                  <Skeleton className="size-8 rounded-full" />
                  <Skeleton className="h-4 flex-1" />
                </div>
              ))}
            </div>
          ) : data.recent_activity.length === 0 ? (
            <p className="p-6 text-center text-sm text-muted-foreground">
              No activity yet — run a scan or start a detection replay to get started.
            </p>
          ) : (
            data.recent_activity.map((item, i) => (
              <motion.div
                key={`${item.type}-${item.id}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <Link
                  href={item.type === "scan" ? `/recon?scan=${item.id}` : `/anomaly?run=${item.id}`}
                  className="flex items-center justify-between gap-3 p-4 text-sm transition-colors hover:bg-muted/50"
                >
                  <div className="flex items-center gap-3">
                    <div className="flex size-8 items-center justify-center rounded-full bg-accent/10 text-accent">
                      {item.type === "scan" ? (
                        <ScanSearch className="size-4" />
                      ) : (
                        <Radar className="size-4" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium">{item.target}</p>
                      <p className="text-xs text-muted-foreground">
                        {item.type === "scan" ? "Recon scan" : "Anomaly detection run"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {timeAgo(item.timestamp)}
                    <ArrowRight className="size-3.5" />
                  </div>
                </Link>
              </motion.div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function LaunchCard({
  href,
  icon: Icon,
  title,
  description,
}: {
  href: string;
  icon: typeof ScanSearch;
  title: string;
  description: string;
}) {
  return (
    <Link href={href} className="group">
      <motion.div
        whileHover={{ y: -3 }}
        transition={{ type: "spring", stiffness: 300, damping: 22 }}
        className="glass-surface relative overflow-hidden rounded-xl p-6"
      >
        <div className="pointer-events-none absolute -right-8 -top-8 size-32 rounded-full bg-accent/10 blur-2xl transition-opacity group-hover:opacity-80" />
        <div className="relative flex items-start justify-between">
          <div className="flex size-11 items-center justify-center rounded-lg bg-accent/10 text-accent">
            <Icon className="size-6" />
          </div>
          <ArrowRight className="size-5 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-accent" />
        </div>
        <h3 className="relative mt-4 text-lg font-semibold">{title}</h3>
        <p className="relative mt-1 text-sm text-muted-foreground">{description}</p>
      </motion.div>
    </Link>
  );
}
