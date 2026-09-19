"use client";

import { motion } from "framer-motion";

/**
 * Subtle moving grid + scan-line behind hero/dashboard sections.
 * UI_UX_SPEC §1: "live feels live" without fighting readability — kept at low
 * opacity, pointer-events disabled, sits behind content (z-0).
 */
export function BackgroundGrid({ className }: { className?: string }) {
  return (
    <div className={`pointer-events-none absolute inset-0 overflow-hidden ${className ?? ""}`}>
      <div className="absolute inset-0 bg-grid opacity-60 [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,black,transparent)]" />
      <motion.div
        className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-accent/40 to-transparent"
        animate={{ top: ["0%", "100%"] }}
        transition={{ duration: 6, repeat: Infinity, ease: "linear" }}
      />
      <div className="absolute -top-40 left-1/2 h-96 w-[60rem] -translate-x-1/2 rounded-full bg-accent/10 blur-[120px]" />
    </div>
  );
}
