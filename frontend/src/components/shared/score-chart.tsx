"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export interface ScorePoint {
  index: number;
  score: number;
}

export function ScoreChart({
  data,
  threshold,
}: {
  data: ScorePoint[];
  threshold: number;
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00E5A0" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#00E5A0" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="index" hide />
        <YAxis
          domain={[0, 1]}
          ticks={[0, 0.25, 0.5, 0.75, 1]}
          width={40}
          tick={{ fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            background: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            fontFamily: "var(--font-mono)",
            fontSize: 12,
          }}
          labelFormatter={() => ""}
          formatter={(value) => [Number(value ?? 0).toFixed(3), "score"]}
        />
        <ReferenceLine
          y={threshold}
          stroke="#FF9F43"
          strokeDasharray="6 4"
          strokeWidth={1.5}
          label={{
            value: `threshold ${threshold.toFixed(2)}`,
            position: "insideTopRight",
            fill: "#FF9F43",
            fontSize: 11,
            fontFamily: "var(--font-mono)",
          }}
        />
        <Area
          type="monotone"
          dataKey="score"
          stroke="#00E5A0"
          strokeWidth={2}
          fill="url(#scoreFill)"
          isAnimationActive
          animationDuration={300}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
