#!/usr/bin/env bash
# Reproduce the experiment table in the README: 7 tracked runs, 4 algorithms.
# The best run (by validation F1) ends up in model/model.joblib.
# Afterwards:  mlflow ui --backend-store-uri sqlite:///mlflow.db
set -euo pipefail
rm -f model/model.joblib model/metrics.json
python train.py --algorithm logreg --C 1.0 --max_iter 500
python train.py --algorithm rf --n_estimators 100 --max_depth 6
python train.py --algorithm rf --n_estimators 200 --max_depth 12
python train.py --algorithm rf --n_estimators 300 --max_depth 20
python train.py --algorithm extratrees --n_estimators 200 --max_depth 16
python train.py --algorithm hgb --learning_rate 0.1 --max_iter 200 --max_depth 6
python train.py --algorithm hgb --learning_rate 0.05 --max_iter 400 --max_depth 8 --register
python export_experiments.py
