"""Database tables: analyses (one per upload) and alerts (flagged records)."""
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utc_now():
    """Current UTC time without timezone info (SQLite stores naive datetimes)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("total_records >= 0", name="ck_total_records_nonneg"),
        CheckConstraint("anomaly_count >= 0 AND anomaly_count <= total_records", name="ck_anomaly_count_range"),
        CheckConstraint("anomaly_percentage >= 0 AND anomaly_percentage <= 100", name="ck_anomaly_pct_range"),
    )

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    total_records = Column(Integer, nullable=False)
    anomaly_count = Column(Integer, nullable=False)
    anomaly_percentage = Column(Float, nullable=False)
    model_name = Column(String(100), nullable=False)
    skipped_records = Column(Integer, nullable=False, default=0)
    contamination = Column(Float, nullable=False)

    # One analysis has many alerts. Deleting an analysis deletes its alerts.
    alerts = relationship("Alert", back_populates="analysis", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    row_number = Column(Integer, nullable=False)  # line number in the CSV file (header = line 1)
    score = Column(Float, nullable=False)  # anomaly score, higher = more unusual
    details = Column(Text, nullable=False)  # JSON text with the flow's features
    created_at = Column(DateTime, nullable=False, default=utc_now)

    analysis = relationship("Analysis", back_populates="alerts")
