"""API endpoints: health, analyze, history, details, delete."""
import json
import logging
import os
import re

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, File, Form, HTTPException, Path, Query, Response, UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Analysis
from app.services.anomaly_detector import DEFAULT_CONTAMINATION, MODEL_NAME, ModelError, detect_anomalies
from app.services.data_processor import DataValidationError, load_and_validate

load_dotenv()
logger = logging.getLogger("netsentinel")
router = APIRouter(prefix="/api", tags=["NetSentinel AI"])

MAX_UPLOAD_BYTES = int(float(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024)
MAX_ALERTS_STORED = 1000  # keep only the highest-scoring flagged records


def clean_filename(name):
    """Keep only the file name (no folders) and replace unusual characters."""
    base = os.path.basename((name or "upload.csv").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)
    return base[:100] or "upload.csv"


def database_error(exc):
    logger.exception("Database error: %s", exc)
    return HTTPException(status_code=500, detail="A database error occurred. Please try again.")


def alert_to_dict(alert):
    return {
        "id": alert.id,
        "row_number": alert.row_number,
        "score": round(alert.score, 4),
        "details": json.loads(alert.details),
    }


def analysis_to_dict(analysis, include_alerts=False):
    data = {
        "id": analysis.id,
        "filename": analysis.filename,
        "created_at": analysis.created_at.isoformat() + "Z",
        "total_records": analysis.total_records,
        "anomaly_count": analysis.anomaly_count,
        "anomaly_percentage": analysis.anomaly_percentage,
        "model_name": analysis.model_name,
        "skipped_records": analysis.skipped_records,
        "contamination": analysis.contamination,
    }
    if include_alerts:
        alerts = sorted(analysis.alerts, key=lambda a: a.score, reverse=True)
        data["alerts"] = [alert_to_dict(a) for a in alerts]
        data["alerts_truncated"] = analysis.anomaly_count > len(alerts)
    return data


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/analyze", status_code=201)
async def analyze(
    file: UploadFile = File(...),
    contamination: float = Form(DEFAULT_CONTAMINATION),
    db: Session = Depends(get_db),
):
    filename = clean_filename(file.filename)
    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Unsupported file type. Please upload a .csv file.")

    # Read at most one byte more than the limit, so we can detect oversized files.
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. The maximum size is {MAX_UPLOAD_BYTES / (1024 * 1024):g} MB.",
        )

    try:
        processed = load_and_validate(content)
        result = detect_anomalies(processed.data, contamination)
    except DataValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ModelError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception:
        logger.exception("Unexpected error while processing upload")
        raise HTTPException(status_code=500, detail="Unexpected error while processing the file.")
    finally:
        del content  # the raw upload is never written to disk and is dropped here

    flagged = result[result["is_anomaly"]].sort_values("anomaly_score", ascending=False)
    total = len(result)
    count = len(flagged)

    analysis = Analysis(
        filename=filename,
        total_records=total,
        anomaly_count=count,
        anomaly_percentage=round(count / total * 100, 2),
        model_name=MODEL_NAME,
        skipped_records=processed.skipped_rows,
        contamination=contamination,
    )
    for row in flagged.head(MAX_ALERTS_STORED).itertuples(index=False):
        details = {
            "timestamp": row.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "protocol": row.protocol,
            "duration": float(row.duration),
            "packets": float(row.packets),
            "bytes": float(row.bytes),
        }
        analysis.alerts.append(
            Alert(row_number=int(row.row_number), score=float(row.anomaly_score), details=json.dumps(details))
        )

    try:
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        return analysis_to_dict(analysis, include_alerts=True)
    except SQLAlchemyError as exc:
        db.rollback()
        raise database_error(exc)


@router.get("/analyses")
def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    try:
        total = db.scalar(select(func.count(Analysis.id)))
        rows = db.scalars(
            select(Analysis).order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(limit).offset(offset)
        ).all()
        return {"total": total, "items": [analysis_to_dict(a) for a in rows]}
    except SQLAlchemyError as exc:
        raise database_error(exc)


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found.")
        return analysis_to_dict(analysis, include_alerts=True)
    except SQLAlchemyError as exc:
        raise database_error(exc)


@router.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int = Path(..., ge=1), db: Session = Depends(get_db)):
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            raise HTTPException(status_code=404, detail="Analysis not found.")
        db.delete(analysis)  # its alerts are deleted too (cascade)
        db.commit()
        return Response(status_code=204)
    except SQLAlchemyError as exc:
        db.rollback()
        raise database_error(exc)
