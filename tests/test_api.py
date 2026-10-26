"""Tests for the REST API, database persistence and the served web page."""
from app.models import Alert, Analysis
from app.routes import analyses as analyses_routes


def upload(client, content, name="flows.csv", **data):
    return client.post("/api/analyze", files={"file": (name, content, "text/csv")}, data=data)


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_upload(client, make_csv):
    response = upload(client, make_csv())
    assert response.status_code == 201
    body = response.json()
    assert body["total_records"] == 105
    assert body["model_name"] == "IsolationForest"
    assert body["anomaly_count"] == len(body["alerts"])
    assert 0 < body["anomaly_percentage"] <= 100
    assert body["alerts"][0]["score"] >= body["alerts"][-1]["score"]


def test_empty_csv_returns_400(client):
    response = upload(client, b"")
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_missing_columns_returns_400(client, make_csv):
    response = upload(client, make_csv(header="timestamp,protocol,duration,packets,other"))
    assert response.status_code == 400
    assert "Missing required column" in response.json()["detail"]


def test_invalid_rows_are_skipped(client, make_csv):
    rows = ["2026-01-01 10:00:00,TCP,abc,5,100", "2026-01-01 10:00:00,TCP,2,5,-1"]
    response = upload(client, make_csv(extra_rows=rows))
    assert response.status_code == 201
    assert response.json()["skipped_records"] == 2


def test_all_invalid_values_return_400(client):
    content = b"timestamp,protocol,duration,packets,bytes\n" + b"2026-01-01 10:00:00,TCP,abc,x,y\n" * 12
    assert upload(client, content).status_code == 400


def test_unsupported_file_type_returns_415(client):
    assert upload(client, b"hello", name="notes.txt").status_code == 415


def test_non_text_csv_returns_400(client):
    assert upload(client, b"\x89PNG\r\n\x1a\n\x00\xff\xfe", name="fake.csv").status_code == 400


def test_oversized_upload_returns_413(client, make_csv, monkeypatch):
    monkeypatch.setattr(analyses_routes, "MAX_UPLOAD_BYTES", 100)
    assert upload(client, make_csv()).status_code == 413


def test_invalid_contamination_returns_422(client, make_csv):
    assert upload(client, make_csv(), contamination="0.9").status_code == 422


def test_results_are_saved_in_database(client, make_csv, session_factory):
    body = upload(client, make_csv()).json()
    with session_factory() as db:
        analysis = db.get(Analysis, body["id"])
        assert analysis is not None
        assert analysis.filename == "flows.csv"
        assert db.query(Alert).filter(Alert.analysis_id == body["id"]).count() == body["anomaly_count"]


def test_unsafe_filename_is_cleaned(client, make_csv):
    body = upload(client, make_csv(), name="..\\..\\evil<name>.csv").json()
    assert "\\" not in body["filename"] and "<" not in body["filename"]


def test_history_lists_newest_first(client, make_csv):
    first = upload(client, make_csv(), name="a.csv").json()["id"]
    second = upload(client, make_csv(), name="b.csv").json()["id"]
    body = client.get("/api/analyses").json()
    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] == [second, first]


def test_get_analysis_details(client, make_csv):
    created = upload(client, make_csv()).json()
    response = client.get(f"/api/analyses/{created['id']}")
    assert response.status_code == 200
    assert response.json()["alerts"] == created["alerts"]


def test_delete_analysis_removes_alerts(client, make_csv, session_factory):
    analysis_id = upload(client, make_csv()).json()["id"]
    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 204
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
    with session_factory() as db:
        assert db.query(Alert).filter(Alert.analysis_id == analysis_id).count() == 0


def test_unknown_id_returns_404(client):
    assert client.get("/api/analyses/9999").status_code == 404
    assert client.delete("/api/analyses/9999").status_code == 404


def test_invalid_id_returns_422(client):
    assert client.get("/api/analyses/abc").status_code == 422
    assert client.get("/api/analyses/0").status_code == 422


def test_error_responses_have_detail_message(client):
    body = client.get("/api/analyses/9999").json()
    assert isinstance(body["detail"], str)


def test_frontend_page_and_assets_are_served(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "NetSentinel AI" in page.text
    assert client.get("/static/js/app.js").status_code == 200
    assert client.get("/static/css/style.css").status_code == 200
