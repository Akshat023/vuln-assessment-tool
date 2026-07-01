"""
Database Models
===============
SQLAlchemy ORM models for PostgreSQL persistence.
"""

from sqlalchemy import Column, String, Text, Float, DateTime, JSON
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    scan_id           = Column(String,   primary_key=True)
    url               = Column(String,   nullable=False)
    status            = Column(String,   default="queued")
    created_at        = Column(String,   nullable=False)
    completed_at      = Column(String,   nullable=True)
    findings          = Column(JSON,     default=list)
    summary           = Column(JSON,     default=dict)
    executive_summary = Column(Text,     default="")
    error             = Column(Text,     nullable=True) 
