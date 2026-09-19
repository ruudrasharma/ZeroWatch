# ZeroWatch — ML Training

This folder contains the actual model training/evaluation work — separate from the FastAPI backend, which only *loads* the trained models at runtime (see `ARCHITECTURE.md`).

## What's here

```
ml/
├── notebooks/
│   └── ZeroWatch_Model_Training.ipynb   ← run this in Google Colab
└── scripts/                              ← (to be added: .py versions of the notebook,
                                              for reproducible/automated re-runs outside Colab)
```

## Running the notebook

1. Open `ZeroWatch_Model_Training.ipynb` in Google Colab (upload it, or push this repo to GitHub and open directly via `File → Open notebook → GitHub`).
2. Runtime → Change runtime type → **GPU** (not required, but trains faster).
3. Run All. No dataset upload needed — NSL-KDD downloads directly from a public URL in Section 2.
4. Section 10 packages all trained model files into `zerowatch_models.zip` and downloads it automatically.
5. Unzip and copy the contents into `backend/models/checkpoints/` in the main repo.

## What the notebook proves

- Trains an **Autoencoder** (PyTorch) purely on normal traffic
- Simulates a zero-day attack via **leave-one-attack-category-out** evaluation: `DoS`, `Probe`, `R2L`, and `U2R` are each held out in turn and never seen during training for that run
- Compares against an **Isolation Forest** baseline and a **Random Forest** supervised baseline (the supervised model is the explicit contrast case — it has no class for the held-out label and can only miss it, mirroring a signature-based system)
- Reports Precision / Recall / F1 / False Positive Rate per held-out category — this table is what backs the "zero-day detection" claim in `PRD.md` and populates the `model_evaluations` table in `DATABASE_SCHEMA.md`
- Explains individual detections with **SHAP**

## Swapping the dataset

The notebook uses NSL-KDD for zero-setup reproducibility (important for an evaluator re-running it). To use CICIDS2017/2018 instead (as originally scoped in `PRD.md`), only Section 2 (data loading) and Section 3 (attack category mapping) need to change — everything from Section 5 onward is dataset-agnostic. See the notebook's final markdown cell for the specific swap notes.
