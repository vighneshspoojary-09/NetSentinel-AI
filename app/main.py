"""NetSentinel AI - application entry point.

Run from the project root with:  uvicorn app.main:app --reload
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import models  # noqa: F401  (makes sure the tables are registered)
from app.database import Base, engine
from app.routes.analyses import router as analyses_router

logging.basicConfig(level=logging.INFO)
BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)  # create the tables if they do not exist
    yield


app = FastAPI(
    title="NetSentinel AI",
    description="Network anomaly detection with Isolation Forest. "
                "Flagged records are potential anomalies that need investigation, not confirmed attacks.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(analyses_router)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(BASE_DIR / "templates" / "index.html")
