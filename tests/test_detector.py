"""Tests for the Isolation Forest detector."""
import pytest

from app.services.anomaly_detector import ModelError, detect_anomalies
from app.services.data_processor import load_and_validate


def run(make_csv, **kwargs):
    data = load_and_validate(make_csv()).data
    return detect_anomalies(data, **kwargs)


def test_every_row_gets_a_prediction_and_score(make_csv):
    result = run(make_csv)
    assert len(result) == 105
    assert result["is_anomaly"].dtype == bool
    assert result["anomaly_score"].notna().all()


def test_obvious_outliers_are_flagged(make_csv):
    result = run(make_csv)
    flagged_rows = set(result.loc[result["is_anomaly"], "row_number"])
    outlier_rows = set(range(102, 107))  # the 5 outliers are the last 5 CSV lines
    assert outlier_rows.issubset(flagged_rows)


def test_outliers_have_higher_scores(make_csv):
    result = run(make_csv)
    outliers = result[result["row_number"] >= 102]["anomaly_score"].mean()
    normal = result[result["row_number"] < 102]["anomaly_score"].mean()
    assert outliers > normal


def test_flag_matches_score_direction(make_csv):
    result = run(make_csv)
    assert (result["is_anomaly"] == (result["anomaly_score"] > 0)).all()


def test_flag_rate_is_close_to_contamination(make_csv):
    result = run(make_csv, contamination=0.05)
    assert abs(result["is_anomaly"].mean() - 0.05) < 0.02


def test_same_seed_gives_same_result(make_csv):
    first = run(make_csv, random_state=1)
    second = run(make_csv, random_state=1)
    assert first["anomaly_score"].equals(second["anomaly_score"])


@pytest.mark.parametrize("bad_value", [0, -0.1, 0.6])
def test_invalid_contamination_is_rejected(make_csv, bad_value):
    with pytest.raises(ModelError):
        run(make_csv, contamination=bad_value)


def test_too_few_rows_is_rejected(make_csv):
    data = load_and_validate(make_csv()).data.head(5)
    with pytest.raises(ModelError):
        detect_anomalies(data)
