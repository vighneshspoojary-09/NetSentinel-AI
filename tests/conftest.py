"""Shared test helpers (pytest loads this file automatically)."""
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base, get_db
from app.main import app

HEADER = "timestamp,protocol,duration,packets,bytes"


def build_csv(n_normal=100, n_outliers=5, extra_rows=(), header=HEADER, seed=0):
    """Make synthetic CSV bytes: normal flows first, then obvious outliers, then any extra raw lines."""
    rng = np.random.default_rng(seed)
    lines = [header]
    for i in range(n_normal):
        proto = "TCP" if i % 3 else "UDP"
        lines.append(
            f"2026-01-01 10:{i % 60:02d}:00,{proto},{rng.uniform(1, 4):.2f},"
            f"{rng.integers(8, 20)},{rng.integers(800, 2000)}"
        )
    for j in range(n_outliers):
        lines.append(f"2026-01-01 11:{j:02d}:00,TCP,{900 + j * 10},{8500 + j * 100},{900000 + j * 5000}")
    lines.extend(extra_rows)
    return ("\n".join(lines) + "\n").encode("utf-8")


@pytest.fixture()
def make_csv():
    return build_csv


@pytest.fixture()
def session_factory():
    """A fresh in-memory database for every test."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def client(session_factory):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
