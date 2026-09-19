"use client";

import { motion, useMotionValue, useTransform, animate } from "framer-motion";
import { useEffect, useState } from "react";
import { riskScoreSeverity } from "@/lib/severity";
import { SEVERITY_BG } from "@/lib/severity";
import { cn } from "@/lib/utils";

const SIZE = 200;
const STROKE = 14;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function RiskGauge({
  score,
  className,
  size = SIZE,
}: {
  score: number;
  className?: string;
  size?: number;
}) {
  const severity = riskScoreSeverity(score);
  const color = SEVERITY_BG[severity];
  const progress = useMotionValue(0);
  const [display, setDisplay] = useState(0);
  const offset = useTransform(
    progress,
    (v) => CIRCUMFERENCE - (v / 100) * CIRCUMFERENCE,
  );

  useEffect(() => {
    const controls = animate(progress, score, {
      duration: 1.3,
      ease: [0.16, 1, 0.3, 1],
    });
    const unsub = progress.on("change", (v) => setDisplay(Math.round(v)));
    return () => {
      controls.stop();
      unsub();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [score]);

  const scale = size / SIZE;

  return (
    <div
      className={cn("relative inline-flex items-center justify-center", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} viewBox={`0 0 ${SIZE} ${SIZE}`} className="-rotate-90">
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="var(--muted)"
          strokeWidth={STROKE}
        />
        <motion.circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          style={{ strokeDashoffset: offset, filter: `drop-shadow(0 0 8px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ transform: `scale(${scale})` }}>
        <span className="font-mono text-5xl font-bold tabular-nums" style={{ color }}>
          {display}
        </span>
        <span className="text-xs uppercase tracking-widest text-muted-foreground">
          risk score
        </span>
      </div>
    </div>
  );
}
