# UI/UX Specification — ZeroWatch

## 1. Design principles

- **Security-tool aesthetic**: dark mode as default, high-contrast severity colors, monospace accents for technical data (IPs, hashes, ports).
- **Live feels live**: anything real-time (traffic feed, scores) should visibly move/update, not just refresh on a timer.
- **Explainability is never hidden**: every AI-driven flag (recon finding or anomaly alert) must have a one-click path to "why was this flagged."

## 2. Design system

| Token | Value |
|---|---|
| Primary background | `#0B0F14` (near-black, dark mode default) |
| Surface/card background | `#141A22` |
| Primary accent | `#00E5A0` (signal green — "clean/safe") |
| Critical | `#FF4C61` |
| High | `#FF9F43` |
| Medium | `#FFD645` |
| Low/info | `#4DA6FF` |
| Text primary | `#E8EDF2` |
| Text muted | `#8A95A5` |
| Font (UI) | Inter |
| Font (technical/mono data) | JetBrains Mono |
| Light mode | Inverted palette, same accent/severity hues, WCAG AA contrast maintained |

## 3. Screens

### 3.1 Landing page
- Hero headline: "Paste a URL or stream traffic — AI finds what signatures miss."
- Two primary CTAs: "Scan a Website" and "Explore Zero-Day Detection"
- Live counter strip: total scans run, total anomalies detected (seeded values acceptable for demo)
- Footer: "Runs 100% locally — nothing leaves this machine"

### 3.2 Dashboard (post-entry)
- Top row: 3 summary cards — Total Scans, Avg Risk Score, Anomalies Flagged (7-day)
- Recent activity feed (last 5 scans/detections, clickable)
- Two large launch cards: "Recon Engine" / "Zero-Day Engine"

### 3.3 Recon Engine — Scan page
- URL input field + "I own this domain / have authorization" required checkbox (submit disabled until checked)
- Progress stepper: Checking SSL → Fingerprinting → Cross-referencing CVEs → Checking exposure → Generating report
- Results view:
  - Large circular risk score gauge (0–100, color mapped to severity scale)
  - Findings list: collapsible cards, color-coded left border by severity, each expands to show detail + AI remediation text
  - "Export PDF" button, top right

### 3.4 Anomaly Engine — Live dashboard
- Top control bar: dataset/held-out category selector, model selector (Autoencoder / Isolation Forest / RF baseline), threshold slider, Start/Stop replay button
- Left panel (40% width): scrolling live traffic table — flow ID, src/dst IP, protocol, anomaly score bar (inline mini-bar, not just a number)
- Center panel: real-time line chart, anomaly score over time, horizontal threshold line overlaid, flagged points highlighted
- Right panel: "Flagged Alerts" list, newest on top, severity-colored
- Alert detail (modal or slide-over): SHAP horizontal bar chart of top contributing features, model confidence %, side-by-side "Signature match: none" vs "AI verdict: anomalous"

### 3.5 Evaluation page
- Leave-one-attack-out results table: held-out category | precision | recall | F1 | FPR
- Confusion matrix (heatmap style)
- Model comparison bar chart (Autoencoder vs Isolation Forest vs RF baseline, grouped by metric)

### 3.6 History page
- Filterable/sortable table: date, type (Recon/Anomaly), target/category, risk or alert count, severity
- Row click → full report view (reuses Results/Alert detail components)

### 3.7 Settings (minimal for local single-user tool)
- Theme toggle (dark/light)
- Ollama model selector (if multiple pulled locally)
- Data reset button (clears local SQLite history)

## 4. Component inventory

- `RiskGauge` — circular 0–100 gauge, color-mapped
- `SeverityBadge` — pill component, 4 severity levels
- `FindingCard` — collapsible, used in Recon results and History
- `LiveTrafficRow` — table row with inline anomaly score bar
- `ScoreChart` — line chart with threshold overlay (Recharts)
- `ShapBarChart` — horizontal bar chart, feature name + contribution weight
- `AlertCard` — used in live feed and History
- `ProgressStepper` — used during scan execution
- `StatCard` — dashboard summary cards

## 5. Responsive behavior

- Breakpoints: mobile (<640px), tablet (640–1024px), desktop (>1024px)
- Anomaly Engine live dashboard: on tablet/mobile, panels stack vertically (traffic feed → chart → alerts) instead of 3-column layout; live feed truncates to last 10 rows on small screens
- Recon results: findings list is full-width on all breakpoints; risk gauge shrinks but stays visible above the fold
- Navigation collapses to a hamburger/bottom-tab pattern below 640px

## 6. Accessibility

- All severity information conveyed by color also includes a text label/icon (never color-only)
- Minimum WCAG AA contrast on both themes
- Live-updating regions (traffic feed, score chart) use `aria-live="polite"` regions for the alert list specifically (not the full scrolling feed, to avoid announcement spam)
