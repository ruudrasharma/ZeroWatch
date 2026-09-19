"use client";

import { useState } from "react";
import { useTheme } from "next-themes";
import { toast } from "sonner";
import { Settings as SettingsIcon, Moon, Sun, Trash2, Bot, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useSettings, useSetOllamaModel, useResetLocalData } from "@/hooks/use-settings";
import { Skeleton } from "@/components/ui/skeleton";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { data: settings, isLoading } = useSettings();
  const setModel = useSetOllamaModel();
  const resetData = useResetLocalData();
  const [confirmOpen, setConfirmOpen] = useState(false);

  function handleReset() {
    resetData.mutate(undefined, {
      onSuccess: (res) => {
        toast.success(
          `Cleared ${res.scans_deleted} scan(s) and ${res.detection_runs_deleted} detection run(s).`,
        );
        setConfirmOpen(false);
      },
      onError: () => toast.error("Failed to reset local data."),
    });
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold">
          <SettingsIcon className="size-5 text-accent" /> Settings
        </h1>
        <p className="text-sm text-muted-foreground">
          Local, single-user tool — everything here is stored on this machine.
        </p>
      </div>

      {/* Theme */}
      <section className="rounded-xl border bg-card p-5">
        <h2 className="mb-4 text-sm font-semibold">Appearance</h2>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm">
            {theme === "dark" ? <Moon className="size-4" /> : <Sun className="size-4" />}
            Dark mode
          </div>
          <Switch
            checked={theme === "dark"}
            onCheckedChange={(checked) => setTheme(checked ? "dark" : "light")}
          />
        </div>
      </section>

      {/* Ollama */}
      <section className="rounded-xl border bg-card p-5">
        <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold">
          <Bot className="size-4" /> Local LLM (Ollama)
        </h2>
        {isLoading ? (
          <Skeleton className="h-10 w-full" />
        ) : !settings?.ollama_available ? (
          <div className="flex items-center gap-2 rounded-lg border border-medium/30 bg-medium/10 p-3 text-sm text-medium">
            <WifiOff className="size-4 shrink-0" />
            Ollama isn&apos;t reachable at {settings?.ollama_base_url ?? "localhost:11434"}.
            Report/remediation text falls back to labeled placeholder copy until
            it&apos;s running (<code className="whitespace-nowrap font-mono">ollama serve</code>).
          </div>
        ) : (
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Active model</label>
            <Select
              value={settings.active_model}
              onValueChange={(v) =>
                setModel.mutate(v, {
                  onSuccess: () => toast.success(`Switched active model to ${v}.`),
                  onError: () => toast.error("Failed to switch model."),
                })
              }
            >
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {settings.available_models.length === 0 ? (
                  <SelectItem value={settings.active_model}>{settings.active_model}</SelectItem>
                ) : (
                  settings.available_models.map((m) => (
                    <SelectItem key={m} value={m}>{m}</SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>
        )}
      </section>

      {/* Data reset */}
      <section className="rounded-xl border border-critical/30 bg-critical/5 p-5">
        <h2 className="mb-1 text-sm font-semibold text-critical">Reset local data</h2>
        <p className="mb-4 text-sm text-muted-foreground">
          Permanently deletes all scan and detection-run history from the local
          SQLite database. Trained-model evaluation results are not affected.
        </p>
        <Button variant="destructive" size="sm" className="gap-1.5" onClick={() => setConfirmOpen(true)}>
          <Trash2 className="size-3.5" /> Reset local data
        </Button>
      </section>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset local data?</DialogTitle>
            <DialogDescription>
              This permanently deletes every scan and detection run stored
              locally. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleReset} disabled={resetData.isPending}>
              {resetData.isPending ? "Resetting…" : "Yes, delete everything"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
