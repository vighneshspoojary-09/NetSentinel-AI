"""Evaluate NetSentinel's detector on the UNSW-NB15 labelled testing set.

What this script does
---------------------
1. Reads UNSW_NB15_testing-set.csv (columns used: dur, proto, spkts, dpkts, sbytes, dbytes, label).
2. Converts it to NetSentinel's format:
     duration = dur,  packets = spkts + dpkts,  bytes = sbytes + dbytes,  protocol = proto
   The 'timestamp' is ARTIFICIAL (the file has none). The model does not use it.
3. Keeps all normal rows and randomly samples attack rows so attacks make up --attack-rate of the file
   (default 5%), because anomaly detection assumes anomalies are rare.
4. Runs the SAME validation and Isolation Forest code the web app uses (3 features).
5. Compares the flags with the true labels and prints precision, recall, F1, false-positive rate, ROC AUC.

Run from the project root:
    python scripts/evaluate_unsw.py --input data/raw/UNSW_NB15_testing-set.csv
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.anomaly_detector import detect_anomalies  # noqa: E402
from app.services.data_processor import load_and_validate  # noqa: E402

NEEDED = ["dur", "proto", "spkts", "dpkts", "sbytes", "dbytes", "label"]


def convert(raw: pd.DataFrame, attack_rate: float, seed: int) -> tuple[pd.DataFrame, pd.Series]:
    """Return (NetSentinel-format dataframe, true labels 0/1) with attacks sampled to attack_rate."""
    missing = [c for c in NEEDED if c not in raw.columns]
    if missing:
        raise SystemExit(f"Missing expected column(s) in the UNSW file: {missing}\nColumns found: {list(raw.columns)}")

    raw = raw[NEEDED].copy()
    raw["label"] = pd.to_numeric(raw["label"], errors="coerce")
    raw = raw[raw["label"].isin([0, 1])]
    normal = raw[raw["label"] == 0]
    attacks = raw[raw["label"] == 1]
    if len(normal) == 0 or len(attacks) == 0:
        raise SystemExit("The file must contain both normal (label 0) and attack (label 1) rows.")

    n_attack = int(round(len(normal) * attack_rate / (1 - attack_rate)))
    n_attack = max(1, min(n_attack, len(attacks)))
    sample = pd.concat([normal, attacks.sample(n=n_attack, random_state=seed)])
    sample = sample.sample(frac=1, random_state=seed).reset_index(drop=True)  # shuffle

    converted = pd.DataFrame({
        "timestamp": pd.date_range("2026-01-01", periods=len(sample), freq="s").strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": sample["proto"].astype(str),
        "duration": sample["dur"],
        "packets": sample["spkts"] + sample["dpkts"],
        "bytes": sample["sbytes"] + sample["dbytes"],
    })
    return converted, sample["label"].astype(int)


def evaluate(converted: pd.DataFrame, labels: pd.Series, contamination: float, seed: int) -> dict:
    content = converted.to_csv(index=False).encode("utf-8")
    processed = load_and_validate(content)  # same validator as the web app
    result = detect_anomalies(processed.data, contamination=contamination, random_state=seed)

    y_true = labels.to_numpy()[result["row_number"].to_numpy() - 2]  # row_number 2 = first data row
    y_pred = result["is_anomaly"].to_numpy().astype(int)
    scores = result["anomaly_score"].to_numpy()

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "records_evaluated": int(len(result)),
        "rows_skipped_as_invalid": processed.skipped_rows,
        "true_attack_rate": round(float(y_true.mean()), 4),
        "contamination_used": contamination,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="path to UNSW_NB15_testing-set.csv")
    parser.add_argument("--attack-rate", type=float, default=0.05, help="share of attacks kept in the file (0-0.5)")
    parser.add_argument("--contamination", type=float, default=None, help="default: same as attack rate")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--save-csv", default=None, help="optional: also save the converted file for the dashboard")
    args = parser.parse_args()

    if not 0 < args.attack_rate <= 0.5:
        raise SystemExit("--attack-rate must be greater than 0 and at most 0.5")
    contamination = args.contamination if args.contamination is not None else args.attack_rate

    raw = pd.read_csv(args.input)
    converted, labels = convert(raw, args.attack_rate, args.seed)
    if args.save_csv:
        converted.to_csv(args.save_csv, index=False)
        print(f"Saved converted CSV for the dashboard: {args.save_csv}")

    metrics = evaluate(converted, labels, contamination, args.seed)
    report = {
        "dataset_file": Path(args.input).name,
        "run_time": datetime.now().isoformat(timespec="seconds"),
        "model": "IsolationForest (NetSentinel detector)",
        "features": ["duration", "packets", "bytes"],
        "seed": args.seed,
        "attack_rate_in_sample": args.attack_rate,
        "note": "timestamps are artificial; attacks were randomly sampled to the stated rate",
        **metrics,
    }
    print(json.dumps(report, indent=2))
    out = Path("data") / "evaluation_results.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\nSaved to {out}")
    print(f"For comparison, flagging rows at random would give precision of about {metrics['true_attack_rate']}.")


if __name__ == "__main__":
    main()
