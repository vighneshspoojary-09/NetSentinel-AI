"""Tests for CSV validation and cleaning."""
import pytest

from app.services.data_processor import DataValidationError, load_and_validate


def test_valid_csv_is_accepted(make_csv):
    result = load_and_validate(make_csv())
    assert result.rows_in_file == 105
    assert result.skipped_rows == 0
    assert len(result.data) == 105


def test_first_data_row_number_is_2(make_csv):
    result = load_and_validate(make_csv())
    assert result.data["row_number"].iloc[0] == 2


def test_empty_file_is_rejected():
    with pytest.raises(DataValidationError):
        load_and_validate(b"")
    with pytest.raises(DataValidationError):
        load_and_validate(b"   \n  \n")


def test_header_only_is_rejected(make_csv):
    with pytest.raises(DataValidationError):
        load_and_validate(make_csv(n_normal=0, n_outliers=0))


def test_missing_columns_are_named_in_message(make_csv):
    content = make_csv(header="timestamp,protocol,duration,packets,wrong")
    with pytest.raises(DataValidationError) as error:
        load_and_validate(content)
    assert "bytes" in str(error.value)


def test_invalid_rows_are_skipped_and_counted(make_csv):
    bad_rows = [
        "2026-01-01 10:00:00,TCP,abc,5,100",   # text instead of a number
        "2026-01-01 10:00:00,TCP,2,5,-1",      # negative value
        "2026-01-01 10:00:00,TCP,inf,5,100",   # infinite value
        "2026-01-01 10:00:00,TCP,,5,100",      # missing value
        "not-a-date,TCP,2,5,100",              # bad timestamp
    ]
    result = load_and_validate(make_csv(extra_rows=bad_rows))
    assert result.skipped_rows == 5
    assert len(result.data) == 105


def test_too_few_valid_rows_is_rejected():
    content = b"timestamp,protocol,duration,packets,bytes\n2026-01-01 10:00:00,TCP,abc,5,100\n"
    with pytest.raises(DataValidationError):
        load_and_validate(content)


def test_binary_file_is_rejected():
    with pytest.raises(DataValidationError):
        load_and_validate(b"\x89PNG\r\n\x1a\n\x00\x00\xff\xfe")


def test_column_names_ignore_case_and_spaces(make_csv):
    content = make_csv(header=" Timestamp , Protocol ,DURATION,Packets,BYTES")
    assert load_and_validate(content).skipped_rows == 0
