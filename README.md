# NetSentinel AI

AI-powered network anomaly detection and analysis platform (BCA student project).

Upload a network-flow CSV file. The app validates it, runs an **Isolation Forest** model, flags unusual
records, saves the analysis in SQLite and shows the results in a web dashboard.

> **Important:** An anomaly is not automatically a cyberattack. Flagged records are *potential anomalies that need
> further investigation*. This project has **not** been evaluated on real attack data, so it must not be presented as
> a reliable attack detector.

## Status

| Feature | Status |
|---|---|
| CSV upload, validation, cleaning | Implemented |
| Isolation Forest + anomaly score | Implemented |
| SQLite storage (analyses, alerts) | Implemented |
| REST API (5 endpoints) | Implemented |
| Dashboard (Chart.js) | Implemented |
| Automated tests | Implemented |
| Evaluation on a labelled dataset (CIC-IDS2017 / UNSW-NB15) | Planned |
| AI explanations, RAG, real-time monitoring, e-mail alerts | Planned |

## Technology

Python, FastAPI, Uvicorn, Pandas, NumPy, Scikit-learn, SQLAlchemy, SQLite, HTML/CSS/JavaScript, Chart.js, Pytest.

## Setup (Windows, VS Code terminal, project folder)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

## Run

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 for the dashboard and http://127.0.0.1:8000/docs for the interactive API docs.
Try it with `data/sample_network_flows.csv` (synthetic data).

## Run the tests

```powershell
pytest -v
```

## CSV format

Required columns: `timestamp, protocol, duration, packets, bytes` (column names are not case-sensitive).

```
timestamp,protocol,duration,packets,bytes
2026-01-01 10:00:00,TCP,2.5,12,1500
```

- The model uses `duration`, `packets` and `bytes`. To use another dataset, map its columns to these names.
- Rows with missing, non-numeric, infinite or negative numbers, a bad timestamp or no protocol are **skipped** and
  counted in `skipped_records`.
- The file is **rejected** if it is empty, not readable UTF-8 text, lacks a required column, has more than 100,000 rows,
  or has fewer than 10 valid rows.
- Maximum upload size: `MAX_UPLOAD_MB` in `.env` (default 10 MB). Uploaded files are never saved to disk.

## Anomaly score

`anomaly_score = -decision_function` of scikit-learn's Isolation Forest.

- **Higher = more unusual** compared with the rest of the same file.
- Score above 0 means the record is flagged; the share flagged is steered by `contamination` (default 0.05).
- It is a relative ranking, **not** the probability of an attack.

## API

| Method | Endpoint | Description | Success |
|---|---|---|---|
| GET | `/api/health` | Is the app running | 200 `{"status":"ok"}` |
| POST | `/api/analyze` | multipart form: `file` (.csv), optional `contamination` (0 to 0.5) | 201 analysis + alerts |
| GET | `/api/analyses?limit=50&offset=0` | Past analyses, newest first | 200 `{total, items}` |
| GET | `/api/analyses/{id}` | One analysis with its alerts | 200 |
| DELETE | `/api/analyses/{id}` | Delete analysis and alerts | 204 |

Errors return `{"detail": "message"}` with status 400 (bad data), 413 (too large), 415 (not .csv),
422 (bad parameter), 404 (not found) or 500 (server/database problem).

Example `POST /api/analyze` response (shortened):

```json
{
  "id": 1, "filename": "sample_network_flows.csv", "created_at": "2026-01-01T10:00:00Z",
  "total_records": 126, "anomaly_count": 7, "anomaly_percentage": 5.56,
  "model_name": "IsolationForest", "skipped_records": 0, "contamination": 0.05,
  "alerts": [{"id": 1, "row_number": 125, "score": 0.275,
              "details": {"timestamp": "2026-01-01 12:03:00", "protocol": "TCP",
                          "duration": 1500.0, "packets": 12000.0, "bytes": 2000000.0}}],
  "alerts_truncated": false
}
```

## Project structure

```
app/            application code (main.py, database.py, models.py)
app/services/   data_processor.py (validation), anomaly_detector.py (Isolation Forest)
app/routes/     analyses.py (API endpoints)
app/templates/  index.html     app/static/  css + js (dashboard)
tests/          conftest.py, test_api.py, test_data_processor.py, test_detector.py
data/           SQLite database (ignored by Git) and the synthetic sample CSV
```

## Security notes

Upload size and type limits, cleaned filenames, uploads never executed or stored, no secrets in code (`.env` is
ignored by Git), generic error messages for server errors, and the dashboard inserts server data as text only.
There is **no login or rate limiting**, so do not expose this app on the public internet as it is. Only analyse data
you are authorised to use.

## Limitations

- The sample data is synthetic and says nothing about real-world accuracy.
- Isolation Forest finds *unusual* records, not *malicious* ones; busy-but-legitimate traffic can be flagged.
- Only three numeric features are used.
- Chart.js loads from a CDN, so charts need an internet connection.
