
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
TRAIN_FILE = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_FILE = DATA_DIR / "UNSW_NB15_testing-set.csv"

# Additional numeric features from UNSW-NB15.
FEATURE_COLUMNS = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_src_ltm",
    "ct_srv_dst",
]

def prepare_features(df):
    features = df[FEATURE_COLUMNS].apply(
        pd.to_numeric, errors="coerce"
    )
    features = features.replace(
        [float("inf"), float("-inf")], float("nan")
    )
    return features.fillna(0).clip(lower=0)


def main():
    if not TRAIN_FILE.exists() or not TEST_FILE.exists():
        raise FileNotFoundError(
            "Dataset files not found in data/raw."
        )

    print("Loading UNSW-NB15 datasets...")
    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    for column in FEATURE_COLUMNS + ["label"]:
        if column not in train_df.columns or column not in test_df.columns:
            raise ValueError(f"Required column missing: {column}")

    X_train = prepare_features(train_df)
    X_test = prepare_features(test_df)

    y_train = pd.to_numeric(
        train_df["label"], errors="coerce"
    )
    y_test = pd.to_numeric(
        test_df["label"], errors="coerce"
    )

    # Train only on normal traffic to learn a baseline.
    normal_mask = y_train == 0
    X_train_normal = X_train.loc[normal_mask]

    if len(X_train_normal) < 10 or y_test.isna().any():
        raise ValueError("Insufficient normal data or invalid labels.")

    print(f"Training records: {len(train_df):,}")
    print(f"Normal records used for training: {len(X_train_normal):,}")
    print(f"Testing records: {len(test_df):,}")
    print(f"Features used: {len(FEATURE_COLUMNS)}")
    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_normal)

    y_pred = (model.predict(X_test) == -1).astype(int)
    y_true = y_test.astype(int)

    print("\n=== UNSW-NB15 Evaluation Results ===")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))
    print("\nClassification report:")
    print(classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Attack"],
        zero_division=0,
    ))

    results = test_df[["label", "attack_cat"]].copy()
    results["predicted_attack"] = y_pred
    results["anomaly_score"] = -model.decision_function(X_test)

    output_file = DATA_DIR / "evaluation_results.csv"
    results.to_csv(output_file, index=False)
    print(f"\nDetailed predictions saved to: {output_file}")


if __name__ == "__main__":
    main()
