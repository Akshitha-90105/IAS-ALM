

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import firewall, ids, anomaly
from app.database import engine, Base
from app import models

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SENTINEL",
    description="Intrusion Detection and Firewall Simulator",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(firewall.router)
app.include_router(ids.router)
app.include_router(anomaly.router)


@app.get("/")
def home():
    return {
        "project": "SENTINEL",
        "message": "Intrusion Detection and Firewall Simulator",
        "status": "Running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "backend": "online"
    }
