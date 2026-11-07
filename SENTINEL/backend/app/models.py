
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime

from app.database import Base


class FirewallRuleDB(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    action = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)


class SecurityEventDB(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class IDSAlertDB(Base):
    __tablename__ = "ids_alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, nullable=False)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    message = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
