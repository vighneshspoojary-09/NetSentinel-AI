"""CSV validation and cleaning.

How invalid ROWS are handled
----------------------------
A row is skipped (not analysed) if any of these is true:
  * duration, packets or bytes is missing, not a number, infinite, or negative
  * timestamp is missing or cannot be read as a date/time
  * protocol is missing
The number of skipped rows is reported back to the user.

How invalid FILES are handled
-----------------------------
The whole file is rejected (DataValidationError) if it is empty, is not readable
CSV text, has no data rows, lacks a required column, has too many rows, or has
fewer than MIN_VALID_ROWS usable rows left after cleaning.
"""
import io
from dataclasses import dataclass

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "protocol", "duration", "packets", "bytes"]
NUMERIC_COLUMNS = ["duration", "packets", "bytes"]
MAX_ROWS = 100_000
MIN_VALID_ROWS = 10


class DataValidationError(Exception):
    """The uploaded data cannot be used. The message is safe to show to the user."""


@dataclass
class ProcessedData:
    data: pd.DataFrame  # clean rows only, with an extra 'row_number' column
    rows_in_file: int
    skipped_rows: int


def load_and_validate(content: bytes) -> ProcessedData:
    """Read CSV bytes, validate them and return clean data."""
    if not content or not content.strip():
        raise DataValidationError("The uploaded file is empty.")

    try:
        # Read everything as text first; we convert to numbers ourselves below.
        raw = pd.read_csv(io.BytesIO(content), dtype=str, skipinitialspace=True, encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise DataValidationError("The file is not readable text. Please upload a UTF-8 CSV file.")
    except pd.errors.EmptyDataError:
        raise DataValidationError("The uploaded file is empty.")
    except (pd.errors.ParserError, ValueError):
        raise DataValidationError("The file could not be read as CSV. Please check its format.")

    # Be forgiving about capital letters and spaces in column names.
    raw.columns = [str(c).strip().lower() for c in raw.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in raw.columns]
    if missing:
        raise DataValidationError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Required columns are: {', '.join(REQUIRED_COLUMNS)}."
        )
    if raw.empty:
        raise DataValidationError("The file has a header but no data rows.")
    if len(raw) > MAX_ROWS:
        raise DataValidationError(f"Too many rows ({len(raw)}). The maximum is {MAX_ROWS}.")

    df = raw[REQUIRED_COLUMNS].copy()
    df["row_number"] = np.arange(len(df)) + 2  # line 1 is the header

    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")  # bad text becomes NaN
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    df["protocol"] = df["protocol"].str.strip().str.upper()

    numbers = df[NUMERIC_COLUMNS]
    valid = (
        np.isfinite(numbers).all(axis=1)  # False for NaN and +/- infinity
        & (numbers >= 0).all(axis=1)
        & df["timestamp"].notna()
        & df["protocol"].notna()
        & (df["protocol"] != "")
    )

    clean = df[valid].reset_index(drop=True)
    skipped = int((~valid).sum())

    if len(clean) < MIN_VALID_ROWS:
        raise DataValidationError(
            f"Only {len(clean)} valid row(s) found. At least {MIN_VALID_ROWS} are needed. "
            f"{skipped} row(s) were invalid (missing, non-numeric, infinite or negative values)."
        )

    return ProcessedData(data=clean, rows_in_file=len(df), skipped_rows=skipped)
