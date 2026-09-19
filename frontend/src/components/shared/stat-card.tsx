"use client";

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { AnimatedCounter } from "./animated-counter";
import { cn } from "@/lib/utils";

export function StatCard({
  label,
  value,
  icon: Icon,
  suffix = "",
  decimals = 0,
  accent = false,
  className,
}: {
  label: string;
  value: number;
  icon?: LucideIcon;
  suffix?: string;
  decimals?: number;
  accent?: boolean;
  className?: string;
}) {
  return (
    <motion.div
      whileHover={{ y: -2 }}
      transition={{ type: "spring", stiffness: 300, damping: 22 }}
      className={cn(
        "glass-surface relative overflow-hidden rounded-xl p-5",
        className,
      )}
    >
      {accent && (
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-accent/10 to-transparent" />
      )}
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="mt-2 font-mono text-3xl font-bold tabular-nums">
            <AnimatedCounter value={value} decimals={decimals} suffix={suffix} />
          </p>
        </div>
        {Icon && (
          <div className="rounded-lg bg-accent/10 p-2 text-accent">
            <Icon className="size-5" />
          </div>
        )}
      </div>
    </motion.div>
  );
}
