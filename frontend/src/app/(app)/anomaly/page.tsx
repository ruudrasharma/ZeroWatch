"use client";

import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import { Play, Square, Radar, CircleDot, SlidersHorizontal, History as HistoryIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useDetectionRun, useStartDetectionRun } from "@/hooks/use-detection-runs";
import { useDetectionStream } from "@/hooks/use-detection-stream";
import { LiveTrafficRow } from "@/components/shared/live-traffic-row";
import { AlertCard } from "@/components/shared/alert-card";
import { AlertDetailSheet } from "@/components/shared/alert-detail-sheet";
import { ScoreChart, type ScorePoint } from "@/components/shared/score-chart";
import {
  DETECTION_MODELS,
  HELD_OUT_CATEGORIES,
  type AnomalyAlert,
  type DetectionModel,
  type DetectionRunDetail,
  type HeldOutCategory,
} from "@/lib/api-types";
import { cn } from "@/lib/utils";

function AnomalyPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const runParam = searchParams.get("run");
  const initialRunId = runParam ? Number(runParam) : null;

  const [runId, setRunId] = useState<number | null>(
    initialRunId && !Number.isNaN(initialRunId) ? initialRunId : null,
  );
  // A run started in THIS session is always live (never re-fetched as
  // "historical" mid-session) — see the completed-run gate below for why a
  // URL-provided run id from History needs the extra round-trip first.
  const [startedLocally, setStartedLocally] = useState(false);

  const runMeta = useDetectionRun(!startedLocally && runId != null ? runId : null);

  if (runId != null && !startedLocally && runMeta.isLoading) {
    return <Skeleton className="h-96 rounded-xl" />;
  }
  if (runId != null && !startedLocally && runMeta.data?.completed_at) {
    return (
      <HistoricalRunView
        run={runMeta.data}
        onNewReplay={() => {
          setRunId(null);
          setStartedLocally(false);
          router.replace("/anomaly", { scroll: false });
        }}
      />
    );
  }

  return (
    <LiveDashboard
      runId={runId}
      onRunStarted={(id) => {
        setRunId(id);
        setStartedLocally(true);
        router.replace(`/anomaly?run=${id}`, { scroll: false });
      }}
    />
  );
}

function HistoricalRunView({
  run,
  onNewReplay,
}: {
  run: DetectionRunDetail;
  onNewReplay: () => void;
}) {
  const [selectedAlert, setSelectedAlert] = useState<AnomalyAlert | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold">
            <HistoryIcon className="size-5 text-accent" /> Detection Run #{run.id}
          </h1>
          <p className="font-mono text-sm text-muted-foreground">
            {run.held_out_category} · {run.model_used} · threshold {run.threshold.toFixed(2)}
          </p>
        </div>
        <Button size="sm" className="gap-1.5" onClick={onNewReplay}>
          <Play className="size-3.5" /> New replay
        </Button>
      </div>

      {run.precision != null && (
        <div className="grid grid-cols-2 gap-3 rounded-xl border border-accent/30 bg-accent/5 p-4 sm:grid-cols-4">
          <Metric label="Precision" value={run.precision ?? 0} />
          <Metric label="Recall" value={run.recall ?? 0} />
          <Metric label="F1" value={run.f1_score ?? 0} />
          <Metric label="FPR" value={run.false_positive_rate ?? 0} />
        </div>
      )}

      <div className="rounded-xl border bg-card">
        <PanelHeader title="Flagged alerts" count={run.alerts.length} />
        <div className="max-h-[520px] space-y-2 overflow-y-auto p-2">
          {run.alerts.length === 0 ? (
            <EmptyPanel text="No alerts were flagged during this run." />
          ) : (
            run.alerts.map((a) => (
              <AlertCard key={a.flow_id} alert={a} onClick={() => setSelectedAlert(a)} />
            ))
          )}
        </div>
      </div>

      <AlertDetailSheet
        alert={selectedAlert}
        open={selectedAlert != null}
        onOpenChange={(open) => !open && setSelectedAlert(null)}
      />
    </div>
  );
}

function LiveDashboard({
  runId,
  onRunStarted,
}: {
  runId: number | null;
  onRunStarted: (id: number) => void;
}) {
  const [category, setCategory] = useState<HeldOutCategory>("DoS");
  const [model, setModel] = useState<DetectionModel>("autoencoder");
  const [threshold, setThresholdState] = useState(0.7);
  const [selectedAlert, setSelectedAlert] = useState<AnomalyAlert | null>(null);

  const startRun = useStartDetectionRun();
  const stream = useDetectionStream(runId);

  const running = runId != null && (stream.connectionState === "open" || stream.connectionState === "connecting");

  function handleStart() {
    startRun.mutate(
      { held_out_category: category, model, threshold },
      { onSuccess: (data) => onRunStarted(data.detection_run_id) },
    );
  }

  function handleStop() {
    stream.stop();
  }

  function handleThresholdChange(values: number[]) {
    const value = values[0];
    setThresholdState(value);
    if (running) stream.setThreshold(value);
  }

  const chartData: ScorePoint[] = useMemo(
    () =>
      [...stream.flows]
        .reverse()
        .map((f, i) => ({ index: i, score: f.anomaly_score })),
    [stream.flows],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold">
            <Radar className="size-5 text-accent" /> Zero-Day Anomaly Engine
          </h1>
          <p className="text-sm text-muted-foreground">
            Live dataset replay scored in real time by the active model.
          </p>
        </div>
        <ConnectionBadge state={stream.connectionState} running={running} />
      </div>

      {/* Control bar */}
      <div className="flex flex-col gap-4 rounded-xl border bg-card p-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="grid flex-1 grid-cols-1 gap-4 sm:grid-cols-3">
          <Field label="Held-out category (simulated zero-day)">
            <Select value={category} onValueChange={(v) => setCategory(v as HeldOutCategory)} disabled={running}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {HELD_OUT_CATEGORIES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Model">
            <Select value={model} onValueChange={(v) => setModel(v as DetectionModel)} disabled={running}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {DETECTION_MODELS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label={`Threshold — ${threshold.toFixed(2)}`}>
            <div className="flex items-center gap-2 pt-2">
              <SlidersHorizontal className="size-3.5 shrink-0 text-muted-foreground" />
              <Slider
                value={[threshold]}
                min={0}
                max={1}
                step={0.01}
                onValueChange={handleThresholdChange}
              />
            </div>
          </Field>
        </div>
        <div>
          {running ? (
            <Button variant="destructive" onClick={handleStop} className="gap-1.5">
              <Square className="size-3.5" /> Stop
            </Button>
          ) : (
            <Button onClick={handleStart} disabled={startRun.isPending} className="gap-1.5">
              <Play className="size-3.5" /> Start Replay
            </Button>
          )}
        </div>
      </div>

      {stream.summary && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-2 gap-3 rounded-xl border border-accent/30 bg-accent/5 p-4 sm:grid-cols-4"
        >
          <Metric label="Precision" value={stream.summary.precision} />
          <Metric label="Recall" value={stream.summary.recall} />
          <Metric label="F1" value={stream.summary.f1_score} />
          <Metric label="FPR" value={stream.summary.false_positive_rate} />
        </motion.div>
      )}

      {stream.errorMessage && (
        <p className="rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-critical">
          {stream.errorMessage}
        </p>
      )}

      {/* 3-column live dashboard — stacks on tablet/mobile per UI_UX_SPEC §5 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[2fr_3fr_2fr]">
        <div className="rounded-xl border bg-card">
          <PanelHeader title="Live traffic" count={stream.flows.length} />
          <div className="max-h-[420px] overflow-y-auto">
            {stream.flows.length === 0 ? (
              <EmptyPanel text="No traffic yet — start a replay." />
            ) : (
              // UI_UX_SPEC.md §5: live feed truncates to last 10 rows on small
              // screens — the 11th+ row is hidden below sm, shown from sm up.
              stream.flows
                .slice(0, 30)
                .map((f, i) => (
                  <div key={f.flow_id} className={i >= 10 ? "hidden sm:block" : undefined}>
                    <LiveTrafficRow flow={f} />
                  </div>
                ))
            )}
          </div>
        </div>

        <div className="rounded-xl border bg-card p-2">
          <PanelHeader title="Anomaly score" />
          <div className="h-[380px] w-full p-2">
            {chartData.length === 0 ? (
              <EmptyPanel text="Score chart will draw live once flows start streaming." />
            ) : (
              <ScoreChart data={chartData} threshold={threshold} />
            )}
          </div>
        </div>

        <div className="rounded-xl border bg-card">
          <PanelHeader title="Flagged alerts" count={stream.alerts.length} live />
          <div
            className="max-h-[420px] space-y-2 overflow-y-auto p-2"
            aria-live="polite"
          >
            {stream.alerts.length === 0 ? (
              <EmptyPanel text="Alerts will appear here when anomaly score crosses threshold." />
            ) : (
              stream.alerts.map((a) => (
                <AlertCard key={a.flow_id} alert={a} onClick={() => setSelectedAlert(a)} />
              ))
            )}
          </div>
        </div>
      </div>

      <AlertDetailSheet
        alert={selectedAlert}
        open={selectedAlert != null}
        onOpenChange={(open) => !open && setSelectedAlert(null)}
      />
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="text-xs font-medium text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="font-mono text-xl font-bold tabular-nums">{(value * 100).toFixed(1)}%</p>
    </div>
  );
}

function PanelHeader({ title, count, live }: { title: string; count?: number; live?: boolean }) {
  return (
    <div className="flex items-center justify-between border-b px-3 py-2">
      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {live && <CircleDot className="size-3 animate-pulse text-critical" />}
        {title}
      </div>
      {count != null && (
        <span className="font-mono text-xs text-muted-foreground">{count}</span>
      )}
    </div>
  );
}

function EmptyPanel({ text }: { text: string }) {
  return (
    <div className="flex h-32 items-center justify-center px-4 text-center text-xs text-muted-foreground">
      {text}
    </div>
  );
}

function ConnectionBadge({
  state,
  running,
}: {
  state: string;
  running: boolean;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium",
        running ? "border-accent/40 bg-accent/10 text-accent" : "border-border text-muted-foreground",
      )}
    >
      <span className={cn("size-1.5 rounded-full", running ? "animate-pulse bg-accent" : "bg-muted-foreground")} />
      {running ? "live" : state === "closed" ? "stopped" : "idle"}
    </div>
  );
}

export default function AnomalyPage() {
  return (
    <Suspense fallback={<Skeleton className="h-40 rounded-xl" />}>
      <AnomalyPageInner />
    </Suspense>
  );
}
