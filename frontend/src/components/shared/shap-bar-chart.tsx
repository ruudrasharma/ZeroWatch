"use client";

import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip } from "recharts";

export function ShapBarChart({ shapValues }: { shapValues: Record<string, number> }) {
  const data = Object.entries(shapValues)
    .map(([feature, value]) => ({ feature, value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 5);

  if (data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No SHAP contributions available for this alert.
      </p>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(140, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
        <XAxis type="number" hide />
        <YAxis
          type="category"
          dataKey="feature"
          width={150}
          tickFormatter={(value: string) =>
            value.length > 20 ? `${value.slice(0, 19)}…` : value
          }
          tick={{ fill: "var(--muted-foreground)", fontSize: 10, fontFamily: "var(--font-mono)" }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: "var(--muted)" }}
          contentStyle={{
            background: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            fontFamily: "var(--font-mono)",
            fontSize: 12,
          }}
          formatter={(value) => [Number(value ?? 0).toFixed(4), "contribution"]}
        />
        <Bar dataKey="value" radius={4} isAnimationActive animationDuration={500}>
          {data.map((d) => (
            <Cell key={d.feature} fill={d.value >= 0 ? "#FF4C61" : "#4DA6FF"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
