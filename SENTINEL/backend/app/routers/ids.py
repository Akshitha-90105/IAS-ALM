
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityEventDB, IDSAlertDB

router = APIRouter(prefix="/ids", tags=["Intrusion Detection"])


class SecurityEvent(BaseModel):
    source_ip: str
    event_type: Literal[
        "ssh_failed",
        "telnet",
        "connection_attempt"
    ]
    port: int = Field(ge=1, le=65535)


@router.post("/events")
def create_event(event: SecurityEvent, db: Session = Depends(get_db)):

    new_event = SecurityEventDB(**event.model_dump())
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    generated_alerts = []

    # SSH brute-force detection: 5 failed attempts
    if event.event_type == "ssh_failed":

        count = db.query(SecurityEventDB).filter(
            SecurityEventDB.source_ip == event.source_ip,
            SecurityEventDB.event_type == "ssh_failed"
        ).count()

        if count == 5:
            generated_alerts.append({
                "source_ip": event.source_ip,
                "type": "SSH Brute Force",
                "severity": "HIGH",
                "message": "Five failed SSH login attempts detected."
            })

    # Telnet detection
    elif event.event_type == "telnet":

        generated_alerts.append({
            "source_ip": event.source_ip,
            "type": "Suspicious Telnet Activity",
            "severity": "MEDIUM",
            "message": "Telnet connection attempt detected."
        })

    # Port scan detection: 5 different ports
    elif event.event_type == "connection_attempt":

        unique_ports = db.query(SecurityEventDB.port).filter(
            SecurityEventDB.source_ip == event.source_ip,
            SecurityEventDB.event_type == "connection_attempt"
        ).distinct().count()

        if unique_ports == 5:
            generated_alerts.append({
                "source_ip": event.source_ip,
                "type": "Port Scan",
                "severity": "HIGH",
                "message": "Five different ports accessed from one IP."
            })

    # Save generated alerts in SQLite
    for alert in generated_alerts:
        db.add(IDSAlertDB(**alert))

    db.commit()

    return {
        "event": event.model_dump(),
        "alerts_generated": generated_alerts,
        "total_alerts": db.query(IDSAlertDB).count()
    }


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    alerts = db.query(IDSAlertDB).order_by(
        IDSAlertDB.id.desc()
    ).all()

    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "type": a.type,
            "severity": a.severity,
            "message": a.message,
            "timestamp": a.timestamp
        }
        for a in alerts
    ]


@router.get("/events")
def list_events(db: Session = Depends(get_db)):
    events = db.query(SecurityEventDB).order_by(
        SecurityEventDB.id.desc()
    ).all()

    return [
        {
            "id": e.id,
            "source_ip": e.source_ip,
            "event_type": e.event_type,
            "port": e.port,
            "timestamp": e.timestamp
        }
        for e in events
    ]
