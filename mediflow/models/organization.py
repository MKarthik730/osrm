# ============================================================
#  crimson/mediflow_db/models/organization.py
#  Schema: ORGANIZATION
#  Tables: hospitals, branches, departments, rooms
# ============================================================

import uuid
from sqlalchemy import Column, String, Boolean, Integer, Float, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from mediflow_db.database import Base


class Hospital(Base):
    __tablename__ = "hospitals"
    __table_args__ = {"schema": "organization"}

    hospital_id   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name          = Column(String(200), nullable=False)
    chain_name    = Column(String(200))
    country       = Column(String(100))
    contact_info  = Column(JSON)
    is_active     = Column(Boolean, default=True)

    # Relationships
    branches      = relationship("Branch", back_populates="hospital")


class Branch(Base):
    __tablename__ = "branches"
    __table_args__ = {"schema": "organization"}

    branch_id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hospital_id     = Column(UUID(as_uuid=True), ForeignKey("organization.hospitals.hospital_id"), nullable=False)
    branch_name     = Column(String(200), nullable=False)
    city            = Column(String(100))
    address         = Column(Text)
    latitude        = Column(Float)
    longitude       = Column(Float)
    total_capacity  = Column(Integer, default=100)
    current_load    = Column(Float, default=0.0)
    is_active       = Column(Boolean, default=True)
    contact_info    = Column(JSON)

    # Relationships
    hospital        = relationship("Hospital", back_populates="branches")
    departments     = relationship("Department", back_populates="branch")


class Department(Base):
    __tablename__ = "departments"
    __table_args__ = {"schema": "organization"}

    department_id   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    branch_id       = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"), nullable=False)
    name            = Column(String(200), nullable=False)
    specialty       = Column(String(200))
    floor_number    = Column(Integer)
    is_active       = Column(Boolean, default=True)

    # Relationships
    branch          = relationship("Branch", back_populates="departments")
    rooms           = relationship("Room", back_populates="department")


class Room(Base):
    __tablename__ = "rooms"
    __table_args__ = {"schema": "organization"}

    room_id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    department_id   = Column(UUID(as_uuid=True), ForeignKey("organization.departments.department_id"), nullable=False)
    room_number     = Column(String(20), nullable=False)
    room_type       = Column(String(100))   # consultation, operation, emergency
    is_available    = Column(Boolean, default=True)

    # Relationships
    department      = relationship("Department", back_populates="rooms")
