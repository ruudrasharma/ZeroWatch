"use client";

import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScanSearch, Radar, Shield, Lock } from "lucide-react";
import { BootScreen } from "@/components/shared/boot-screen";
import { BackgroundGrid } from "@/components/shared/background-effects";
import { AnimatedCounter } from "@/components/shared/animated-counter";
import { Button } from "@/components/ui/button";
import { useDashboardSummary } from "@/hooks/use-dashboard";

export default function LandingPage() {
  const [booted, setBooted] = useState(false);
  const { data } = useDashboardSummary();

  return (
    <>
      <BootScreen onComplete={() => setBooted(true)} />
      <div className="relative flex min-h-screen flex-col overflow-hidden">
        <BackgroundGrid className="h-[600px]" />

        <header className="relative z-10 flex items-center justify-between px-6 py-5 sm:px-10">
          <div className="flex items-center gap-2 font-semibold">
            <Shield className="size-5 text-accent" />
            ZeroWatch
          </div>
          <Link href="/dashboard">
            <Button variant="outline" size="sm">
              Open app
            </Button>
          </Link>
        </header>

        <main className="relative z-10 mx-auto flex max-w-4xl flex-1 flex-col items-center justify-center px-6 py-20 text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={booted ? { opacity: 1, scale: 1 } : {}}
            transition={{ duration: 0.5 }}
            className="mb-5 inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs font-medium text-accent"
          >
            <Lock className="size-3" /> 100% local — no cloud, no telemetry
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 24 }}
            animate={booted ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
            className="text-4xl font-bold tracking-tight sm:text-6xl"
          >
            Paste a URL or stream traffic —{" "}
            <span className="bg-gradient-to-r from-accent to-low bg-clip-text text-transparent">
              AI finds what signatures miss.
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={booted ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-5 max-w-2xl text-balance text-muted-foreground sm:text-lg"
          >
            ZeroWatch pairs a known-vulnerability Recon Engine with an unsupervised
            Zero-Day Anomaly Detection Engine — fully local, explainable, and
            demo-ready in minutes.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={booted ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="mt-8 flex flex-col gap-3 sm:flex-row"
          >
            <Link href="/recon">
              <Button size="lg" className="gap-2">
                <ScanSearch className="size-4" /> Scan a Website
              </Button>
            </Link>
            <Link href="/anomaly">
              <Button size="lg" variant="outline" className="gap-2">
                <Radar className="size-4" /> Explore Zero-Day Detection
              </Button>
            </Link>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={booted ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.45 }}
            className="mt-16 grid w-full grid-cols-3 gap-4 border-t pt-8"
          >
            <CounterStat label="Total scans" value={data?.total_scans ?? 0} />
            <CounterStat
              label="Anomalies flagged (7d)"
              value={data?.anomalies_flagged_7d ?? 0}
            />
            <CounterStat
              label="Avg risk score"
              value={data?.avg_risk_score ?? 0}
              decimals={data?.avg_risk_score != null ? 1 : 0}
            />
          </motion.div>
        </main>

        <footer className="relative z-10 py-6 text-center text-xs text-muted-foreground">
          Runs 100% locally — nothing leaves this machine.
        </footer>
      </div>
    </>
  );
}

function CounterStat({
  label,
  value,
  decimals = 0,
}: {
  label: string;
  value: number;
  decimals?: number;
}) {
  return (
    <div>
      <p className="font-mono text-2xl font-bold tabular-nums text-accent sm:text-3xl">
        <AnimatedCounter value={value} decimals={decimals} />
      </p>
      <p className="mt-1 text-xs text-muted-foreground">{label}</p>
    </div>
  );
}
