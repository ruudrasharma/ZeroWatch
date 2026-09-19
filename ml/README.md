# ZeroWatch — ML Training

This folder contains the actual model training/evaluation work — separate from the FastAPI backend, which only *loads* the trained models at runtime (see `ARCHITECTURE.md`).

## What's here

```
ml/
├── notebooks/
│   └── ZeroWatch_Model_Training.ipynb   ← the original, run this in Google Colab
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

Downloads NSL-KDD directly (public URL, no auth), runs the full
leave-one-attack-out evaluation across `DoS`/`Probe`/`R2L`/`U2R`, trains the
production Autoencoder + Isolation Forest + Random Forest, and writes all 7
checkpoint files plus `leave_one_out_results.csv` straight into
`backend/models/checkpoints/` — ready for the backend to load on next
startup, no manual zip/unzip step.

Takes a few minutes on CPU (no GPU required — the models are small). For a
fast correctness check of the pipeline itself rather than a real training
run, use `--quick` (subsamples the dataset, reduces epochs/estimators):

```bash
python -m ml.scripts.train --output-dir /tmp/ml_smoke --quick
```

## Running the notebook (alternative — if you want Colab's plots/SHAP demo cells)

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

The notebook uses NSL-KDD for zero-setup reproducibility (important for an evaluator re-running it). To use CICIDS2017/2018 instead (as originally scoped in `PRD.md`), only Section 2 (data loading) and Section 3 (attack category mapping) need to change — everything from Section 5 onward is dataset-agnostic. See the notebook's final markdown cell for the specific swap notes.
