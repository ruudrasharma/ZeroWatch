# ZeroWatch — ML Training

This folder contains the actual model training/evaluation work — separate from the FastAPI backend, which only *loads* the trained models at runtime (see `ARCHITECTURE.md`).

## What's here

```
ml/
├── notebooks/
│   ├── CSL236_MidTerm.ipynb              ← course mid-term: preprocessing stages A–H, fully executed
│   ├── CSL236_MidTerm.pdf                ← PDF export of the executed notebook
│   └── ZeroWatch_Model_Training.ipynb   ← ORIGINAL Colab notebook — superseded, see note below
├── tests/                                ← preprocessing leakage tests: python -m pytest ml/tests
├── scripts/                              ← .py port of the notebook, for reproducible/
│   ├── data.py                              automated re-runs outside Colab (no Colab
│   ├── preprocess.py                        account needed, no manual "download the zip
│   ├── models.py                            and copy it in" step)
│   ├── evaluate.py
│   └── train.py                          ← CLI entrypoint, see below
└── requirements.txt                      ← training-only deps (superset of backend's)
```

## Running the training script (recommended — no Colab account needed)

```bash
cd ZeroWatch   # repo root
python -m venv ml/venv && source ml/venv/bin/activate   # or reuse backend/venv
pip install -r ml/requirements.txt
python -m ml.scripts.train --output-dir backend/models/checkpoints
```

Unlike the notebook, this also saves `isolation_forest.pkl` (trained on all
normal traffic, same convention as the production Autoencoder) — the
notebook only ever fits a per-held-out-category Isolation Forest for the
evaluation table and never persisted a production one, which is why
`backend/services/model_loader.score_isolation_forest()` used to be a proxy
that silently delegated to the Autoencoder's score instead.

Downloads NSL-KDD directly (public URL, no auth), drops the ~600 exact duplicate
rows, runs the full leave-one-attack-out evaluation across `DoS`/`Probe`/`R2L`/`U2R`
and writes, straight into `backend/models/checkpoints/`:

- `autoencoder.pt`, `isolation_forest.pkl`, `random_forest_baseline.pkl` and the two threshold `.pkl`s
- `preprocessor.pkl` (+ `raw_feature_cols.pkl`, `feature_cols.pkl`) — the fitted preprocessing pipeline
- `leave_one_out_results.csv` (thresholded metrics) and `leave_one_out_auc.csv` (ROC-AUC / PR-AUC)
- `preprocessing_report.json` — which columns were one-hot / log-transformed / dropped and why

It also writes `backend/data/processed/nsl_kdd_test.csv` (raw rows the production
Autoencoder never trained on) so the live dashboard replays real traffic instead of
synthetic scores; pass `--no-replay` to skip it. The production models are the ones from
one leave-one-out run (`--production-rf-category`, default `Probe`) together with that
run's preprocessor, so every checkpoint matches the preprocessing that produced it.

### Preprocessing is leakage-free

Everything that learns from data (one-hot categories, which columns to log-transform,
the correlation filter, means/variances) is fitted on the **training rows of each split
only** (`ml/scripts/preprocess.py`). The held-out attack category and the test rows never
influence a fitted statistic — the earlier version fitted its scaler on the whole dataset
before splitting, which leaked the very zero-day traffic the evaluation is meant to be
blind to. Nominal columns (`protocol_type`, `service`, `flag`) are one-hot encoded, skewed
byte/count columns get `log1p`, constant and highly correlated (|r| > 0.95) columns are
dropped. `python -m pytest ml/tests` checks these guarantees.

Takes a few minutes on CPU (no GPU required — the models are small). For a
fast correctness check of the pipeline itself rather than a real training
run, use `--quick` (subsamples the dataset, reduces epochs/estimators):

```bash
python -m ml.scripts.train --output-dir /tmp/ml_smoke --quick
```

## Running the original notebook (alternative — if you want Colab's plots/SHAP demo cells)

> **Superseded.** `ZeroWatch_Model_Training.ipynb` still contains the original preprocessing
> (scaler fitted before the split, label-encoded nominal columns). Use `ml/scripts` for
> checkpoints, and `CSL236_MidTerm.ipynb` for the correct, explained preprocessing stages.

1. Open `ZeroWatch_Model_Training.ipynb` in Google Colab (upload it, or push this repo to GitHub and open directly via `File → Open notebook → GitHub`).
2. Runtime → Change runtime type → **GPU** (not required, but trains faster).
3. Run All. No dataset upload needed — NSL-KDD downloads directly from a public URL in Section 2.
4. Section 10 packages all trained model files into `zerowatch_models.zip` and downloads it automatically.
5. Unzip and copy the contents into `backend/models/checkpoints/` in the main repo.

The notebook still has value the script doesn't: the F1-by-category bar
chart, the confusion-matrix heatmap, and the SHAP summary plot (Sections
8-9) are all visual/exploratory and were kept notebook-only rather than
ported — `ml/scripts` optimizes for reproducible checkpoint generation, not
for regenerating those figures.

## What the notebook proves

- Trains an **Autoencoder** (PyTorch) purely on normal traffic
- Simulates a zero-day attack via **leave-one-attack-category-out** evaluation: `DoS`, `Probe`, `R2L`, and `U2R` are each held out in turn and never seen during training for that run
- Compares against an **Isolation Forest** baseline and a **Random Forest** supervised baseline (the supervised model is the explicit contrast case — it has no class for the held-out label and can only miss it, mirroring a signature-based system)
- Reports Precision / Recall / F1 / False Positive Rate per held-out category — this table is what backs the "zero-day detection" claim in `PRD.md` and populates the `model_evaluations` table in `DATABASE_SCHEMA.md`
- Explains individual detections with **SHAP**

## Swapping the dataset

The pipeline uses NSL-KDD for zero-setup reproducibility. To use CICIDS2017/2018 instead, replace `ml/scripts/data.py` (loading + attack-category mapping) and the column lists at the top of `ml/scripts/preprocess.py` (`NOMINAL_COLS`, `BINARY_COLS`, `RAW_FEATURE_COLS`); the evaluation harness itself is dataset-agnostic. The backend's replay engine and signature rules (`backend/services/anomaly_engine.py`) are NSL-KDD-specific and would need the same swap.
