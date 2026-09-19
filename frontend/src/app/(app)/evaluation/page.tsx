"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { LineChart as LineChartIcon } from "lucide-react";
import { useEvaluations } from "@/hooks/use-evaluations";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

const MODEL_COLORS: Record<string, string> = {
  Autoencoder: "#00E5A0",
  IsolationForest: "#4DA6FF",
  RandomForest: "#FF9F43",
};

const METRICS = [
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "f1_score", label: "F1" },
  { key: "false_positive_rate", label: "FPR" },
] as const;

type MetricKey = (typeof METRICS)[number]["key"];

function heatColor(value: number, invert = false) {
  const v = invert ? 1 - value : value;
  // low -> critical red, high -> accent green
  const hue = 4 + v * 150; // 4 (red-ish) to ~154 (green)
  return `hsl(${hue} 80% ${45 - v * 8}%)`;
}

export default function EvaluationPage() {
  const { data, isLoading } = useEvaluations();
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [chartMetric, setChartMetric] = useState<MetricKey>("f1_score");

  const models = useMemo(
    () => (data ? Array.from(new Set(data.map((r) => r.model_name))) : []),
    [data],
  );
  const categories = useMemo(
    () => (data ? Array.from(new Set(data.map((r) => r.held_out_category))) : []),
    [data],
  );

  const chartData = useMemo(() => {
    if (!data) return [];
    return categories.map((cat) => {
      const row: Record<string, string | number> = { category: cat };
      for (const m of models) {
        const rec = data.find((r) => r.model_name === m && r.held_out_category === cat);
        row[m] = rec ? Number(((rec[chartMetric] ?? 0) as number).toFixed(4)) : 0;
      }
      return row;
    });
  }, [data, categories, models, chartMetric]);

  if (isLoading || !data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold">
          <LineChartIcon className="size-5 text-accent" /> Evaluation
        </h1>
        <p className="text-sm text-muted-foreground">
          Leave-one-attack-out results — real numbers from the trained-model
          evaluation, not the live demo replay.
        </p>
      </div>

      {/* Results table */}
      <div className="overflow-x-auto rounded-xl border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="px-4 py-3 font-medium">Model</th>
              <th className="px-4 py-3 font-medium">Held-out category</th>
              <th className="px-4 py-3 font-medium">Precision</th>
              <th className="px-4 py-3 font-medium">Recall</th>
              <th className="px-4 py-3 font-medium">F1</th>
              <th className="px-4 py-3 font-medium">FPR</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => (
              <motion.tr
                key={`${row.model_name}-${row.held_out_category}`}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.02 }}
                onClick={() => setSelectedCategory(row.held_out_category)}
                className={cn(
                  "cursor-pointer border-b font-mono text-xs transition-colors last:border-b-0 hover:bg-muted/50",
                  selectedCategory === row.held_out_category && "bg-accent/5",
                )}
              >
                <td className="px-4 py-2.5 font-sans font-medium text-foreground">
                  <span
                    className="mr-2 inline-block size-2 rounded-full"
                    style={{ backgroundColor: MODEL_COLORS[row.model_name] ?? "var(--muted-foreground)" }}
                  />
                  {row.model_name}
                </td>
                <td className="px-4 py-2.5">{row.held_out_category}</td>
                <td className="px-4 py-2.5">{row.precision?.toFixed(4) ?? "—"}</td>
                <td className="px-4 py-2.5">{row.recall?.toFixed(4) ?? "—"}</td>
                <td className="px-4 py-2.5">{row.f1_score?.toFixed(4) ?? "—"}</td>
                <td className="px-4 py-2.5">{row.false_positive_rate?.toFixed(4) ?? "—"}</td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Metrics heatmap for selected category */}
      {selectedCategory && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border bg-card p-5"
        >
          <h2 className="mb-4 text-sm font-semibold">
            Per-category breakdown — <span className="font-mono text-accent">{selectedCategory}</span>
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="pb-2 pr-4 font-medium">Model</th>
                  {METRICS.map((m) => (
                    <th key={m.key} className="pb-2 pr-4 font-medium">{m.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {models.map((m) => {
                  const rec = data.find(
                    (r) => r.model_name === m && r.held_out_category === selectedCategory,
                  );
                  if (!rec) return null;
                  return (
                    <tr key={m}>
                      <td className="py-1.5 pr-4 text-xs font-medium">{m}</td>
                      {METRICS.map((metric) => {
                        const value = (rec[metric.key] ?? 0) as number;
                        const invert = metric.key === "false_positive_rate";
                        return (
                          <td key={metric.key} className="py-1.5 pr-4">
                            <div
                              className="flex h-8 w-16 items-center justify-center rounded font-mono text-xs font-semibold text-white"
                              style={{ backgroundColor: heatColor(value, invert) }}
                            >
                              {value.toFixed(3)}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}

      {/* Model comparison chart */}
      <div className="rounded-xl border bg-card p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Model comparison</h2>
          <Select value={chartMetric} onValueChange={(v) => setChartMetric(v as MetricKey)}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              {METRICS.map((m) => (
                <SelectItem key={m.key} value={m.key}>{m.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="category" tick={{ fill: "var(--muted-foreground)", fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis
                domain={[0, 1]}
                tick={{ fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "var(--card)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {models.map((m) => (
                <Bar key={m} dataKey={m} fill={MODEL_COLORS[m] ?? "#8A95A5"} radius={[4, 4, 0, 0]} isAnimationActive animationDuration={600} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
