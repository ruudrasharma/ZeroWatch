# Database Schema — ZeroWatch (SQLite)

Single local file: `zerowatch.db`. No server process required.

## Tables

### `users` (optional — only needed if you implement even a stub login)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| email | TEXT | UNIQUE, NOT NULL |
| display_name | TEXT | |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

### `scans` (Recon Engine runs)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| user_id | INTEGER | FOREIGN KEY → users(id), nullable |
| target_url | TEXT | NOT NULL |
| status | TEXT | NOT NULL — `pending`, `running`, `completed`, `failed` |
| risk_score | INTEGER | 0–100, nullable until completed |
| started_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |
| completed_at | DATETIME | nullable |

### `findings` (individual Recon Engine results, one scan → many findings)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| scan_id | INTEGER | FOREIGN KEY → scans(id), NOT NULL |
| category | TEXT | e.g. `ssl`, `headers`, `cookies`, `cve`, `exposure`, `subdomain` |
| severity | TEXT | `low`, `medium`, `high`, `critical` |
| title | TEXT | NOT NULL |
| description | TEXT | |
| remediation | TEXT | AI-generated |
| raw_data | TEXT | JSON blob of the raw check output |

### `detection_runs` (Zero-Day Anomaly Engine sessions)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| user_id | INTEGER | FOREIGN KEY → users(id), nullable |
| held_out_category | TEXT | NOT NULL — the simulated "unseen" attack category |
| model_used | TEXT | NOT NULL — `autoencoder`, `isolation_forest`, `random_forest` |
| threshold | REAL | NOT NULL |
| started_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |
| completed_at | DATETIME | nullable |
| precision | REAL | nullable, filled at completion |
| recall | REAL | nullable |
| f1_score | REAL | nullable |
| false_positive_rate | REAL | nullable |

### `alerts` (individual flagged flows within a detection run)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| detection_run_id | INTEGER | FOREIGN KEY → detection_runs(id), NOT NULL |
| flow_id | TEXT | NOT NULL — identifier from source dataset |
| anomaly_score | REAL | NOT NULL |
| severity | TEXT | `low`, `medium`, `high`, `critical` |
| src_ip | TEXT | |
| dst_ip | TEXT | |
| protocol | TEXT | |
| shap_values | TEXT | JSON blob: feature name → contribution weight |
| explanation | TEXT | AI-generated plain-English explanation |
| flagged_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

### `model_evaluations` (leave-one-attack-out results, for the Evaluation page)
| Column | Type | Constraints |
|---|---|---|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| model_name | TEXT | NOT NULL |
| held_out_category | TEXT | NOT NULL |
| precision | REAL | |
| recall | REAL | |
| f1_score | REAL | |
| false_positive_rate | REAL | |
| evaluated_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

## Relationships

```
users (1) ──< (many) scans (1) ──< (many) findings
users (1) ──< (many) detection_runs (1) ──< (many) alerts
model_evaluations — standalone reference table, populated once during training/evaluation phase
```

## Indexes

- `scans(target_url)` — for history lookups/filtering
- `scans(status)` — for polling pending/running scans
- `findings(scan_id)`
- `detection_runs(held_out_category)`
- `alerts(detection_run_id)`
- `alerts(severity)` — for filtering the alert list by severity

## Notes

- `raw_data` and `shap_values` are stored as JSON text (SQLite has no native JSON column type but supports `json_extract()` on TEXT columns if querying into the blob is ever needed).
- No cascading deletes configured by default — history is meant to be retained; a manual "reset local data" action in Settings handles clearing, per UI_UX_SPEC.md.
