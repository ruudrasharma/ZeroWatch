"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Shield } from "lucide-react";

const SESSION_KEY = "zerowatch:boot-shown";

const LINES = [
  "Initializing ZeroWatch runtime...",
  "Establishing local process boundary...",
  "Loading detection models... [autoencoder, isolation_forest, random_forest]",
  "Warming up recon engine modules... [ssl, headers, cookies, cve, exposure, subdomain]",
  "Connecting to local LLM (Ollama)...",
  "No data leaves this machine.",
  "Ready.",
];

export function BootScreen({ onComplete }: { onComplete: () => void }) {
  const [skip, setSkip] = useState<boolean | null>(null);
  const [lineIndex, setLineIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const alreadyShown = sessionStorage.getItem(SESSION_KEY) === "1";
    setSkip(alreadyShown);
    if (alreadyShown) onComplete();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (skip !== false) return;
    if (lineIndex >= LINES.length) {
      const t = setTimeout(finish, 450);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setLineIndex((i) => i + 1), 260);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lineIndex, skip]);

  useEffect(() => {
    if (skip !== false) return;
    const target = Math.min(100, (lineIndex / LINES.length) * 100);
    const t = setTimeout(() => setProgress(target), 50);
    return () => clearTimeout(t);
  }, [lineIndex, skip]);

  function finish() {
    sessionStorage.setItem(SESSION_KEY, "1");
    setDone(true);
    setTimeout(onComplete, 550);
  }

  if (skip !== false) return null;

  return (
    <AnimatePresence>
      {!done && (
        <motion.div
          className="fixed inset-0 z-[100] flex flex-col items-center justify-center bg-background"
          exit={{
            clipPath: "inset(0 0 100% 0)",
            transition: { duration: 0.55, ease: [0.76, 0, 0.24, 1] },
          }}
        >
          <div className="absolute inset-0 bg-grid opacity-40 [mask-image:radial-gradient(ellipse_50%_50%_at_50%_50%,black,transparent)]" />

          <motion.div
            initial={{ scale: 0.6, opacity: 0, rotate: -8 }}
            animate={{ scale: 1, opacity: 1, rotate: 0 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
            className="relative mb-8 flex size-20 items-center justify-center rounded-2xl border border-accent/40 bg-accent/10"
          >
            <motion.div
              className="absolute inset-0 rounded-2xl border border-accent/60"
              animate={{ scale: [1, 1.3], opacity: [0.6, 0] }}
              transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut" }}
            />
            <Shield className="size-10 text-accent" strokeWidth={1.5} />
          </motion.div>

          <div className="w-[min(90vw,440px)] space-y-1.5 font-mono text-xs text-muted-foreground">
            {LINES.slice(0, lineIndex).map((line, i) => (
              <motion.p
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                className={i === lineIndex - 1 ? "text-accent" : ""}
              >
                <span className="text-accent/60">$</span> {line}
              </motion.p>
            ))}
          </div>

          <div className="mt-8 h-1 w-[min(90vw,440px)] overflow-hidden rounded-full bg-muted">
            <motion.div
              className="h-full rounded-full bg-accent"
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>

          <button
            onClick={finish}
            className="mt-10 font-mono text-[11px] text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
          >
            skip →
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
