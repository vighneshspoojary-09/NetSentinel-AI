"""Anomaly detection with Isolation Forest.

About the score
---------------
anomaly_score = -(scikit-learn decision_function)
  * HIGHER score  -> the record is MORE unusual compared with the rest of the file
  * score > 0     -> the model flags the record as an anomaly
  * score <= 0    -> the record looks normal
The score is a relative ranking inside ONE file. It is NOT the probability that
an attack happened. A flagged record only needs a human to look at it.
"""
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.services.data_processor import MIN_VALID_ROWS, NUMERIC_COLUMNS

FEATURE_COLUMNS = NUMERIC_COLUMNS  # duration, packets, bytes
MODEL_NAME = "IsolationForest"
DEFAULT_CONTAMINATION = 0.05  # we expect roughly 5% of records to be unusual


class ModelError(Exception):
    """The model could not run. The message is safe to show to the user."""


def detect_anomalies(data: pd.DataFrame, contamination: float = DEFAULT_CONTAMINATION,
                     random_state: int = 42) -> pd.DataFrame:
    """Return a copy of `data` with 'is_anomaly' (bool) and 'anomaly_score' (float) columns."""
    if not 0 < contamination <= 0.5:
        raise ModelError("Contamination must be greater than 0 and at most 0.5.")
    if len(data) < MIN_VALID_ROWS:
        raise ModelError(f"At least {MIN_VALID_ROWS} records are needed for analysis.")
    missing = [c for c in FEATURE_COLUMNS if c not in data.columns]
    if missing:
        raise ModelError(f"Missing feature column(s): {', '.join(missing)}.")

    try:
        features = data[FEATURE_COLUMNS].to_numpy(dtype=float)
        model = IsolationForest(n_estimators=100, contamination=contamination, random_state=random_state)
        model.fit(features)
        labels = model.predict(features)  # -1 = anomaly, 1 = normal
        scores = -model.decision_function(features)
    except Exception as exc:
        raise ModelError("The anomaly-detection model failed to run on this data.") from exc

    result = data.copy()
    result["is_anomaly"] = labels == -1
    result["anomaly_score"] = scores
    return result
