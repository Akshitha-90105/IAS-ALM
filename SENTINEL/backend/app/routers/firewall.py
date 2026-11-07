

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import FirewallRuleDB

router = APIRouter(prefix="/firewall", tags=["Firewall"])


class Packet(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: Literal["TCP", "UDP"]
    port: int = Field(ge=1, le=65535)


class FirewallRule(BaseModel):
    name: str
    protocol: Literal["TCP", "UDP", "ANY"]
    port: int | None = Field(default=None, ge=1, le=65535)
    action: Literal["ALLOW", "BLOCK"]
    enabled: bool = True


@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    return db.query(FirewallRuleDB).all()


@router.post("/rules")
def create_rule(rule: FirewallRule, db: Session = Depends(get_db)):
    new_rule = FirewallRuleDB(**rule.model_dump())

    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    return new_rule


@router.post("/evaluate")
def check_packet(packet: Packet, db: Session = Depends(get_db)):

    rules = db.query(FirewallRuleDB).order_by(
        FirewallRuleDB.id
    ).all()

    for rule in rules:

        if not rule.enabled:
            continue

        protocol_match = (
            rule.protocol == "ANY"
            or rule.protocol == packet.protocol
        )

        port_match = (
            rule.port is None
            or rule.port == packet.port
        )

        if protocol_match and port_match:
            return {
                "packet": packet.model_dump(),
                "decision": rule.action,
                "matched_rule": rule.name,
                "message": f"Packet {rule.action} by firewall"
            }

    return {
        "packet": packet.model_dump(),
        "decision": "BLOCK",
        "matched_rule": "Default Policy",
        "message": "No matching rule. Packet blocked."
    }
