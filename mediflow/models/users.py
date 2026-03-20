# ============================================================
#  crimson/mediflow_db/models/users.py
#  Schema: USERS
#  Tables: patients, doctors, staff, user_auth
# ============================================================

import uuid
from sqlalchemy import Column, String, Boolean, Integer, Float, ForeignKey, Date, JSON, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum
from mediflow_db.database import Base


class RoleEnum(str, enum.Enum):
    patient = "patient"
    doctor  = "doctor"
    staff   = "staff"
    admin   = "admin"


class Patient(Base):
    __tablename__ = "patients"
    __table_args__ = {"schema": "users"}

    patient_id      = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name       = Column(String(200), nullable=False)
    date_of_birth   = Column(Date)
    gender          = Column(String(20))
    blood_group     = Column(String(5))
    phone           = Column(String(20))
    email           = Column(String(200), unique=True)
    address         = Column(String(500))
    emergency_contact = Column(JSON)
    medical_flags   = Column(JSON)        # allergies, chronic conditions
    is_active       = Column(Boolean, default=True)

    # Relationships
    appointments    = relationship("Appointment", back_populates="patient")


class Doctor(Base):
    __tablename__ = "doctors"
    __table_args__ = {"schema": "users"}

    doctor_id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    department_id   = Column(UUID(as_uuid=True), ForeignKey("organization.departments.department_id"))
    full_name       = Column(String(200), nullable=False)
    specialization  = Column(String(200))
    qualification   = Column(String(500))
    experience_yrs  = Column(Integer)
    avg_consult_mins = Column(Float, default=15.0)
    phone           = Column(String(20))
    email           = Column(String(200), unique=True)
    is_active       = Column(Boolean, default=True)

    # Relationships
    time_slots      = relationship("TimeSlot", back_populates="doctor")
    appointments    = relationship("Appointment", back_populates="doctor")


class Staff(Base):
    __tablename__ = "staff"
    __table_args__ = {"schema": "users"}

    staff_id        = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    branch_id       = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"))
    full_name       = Column(String(200), nullable=False)
    role            = Column(String(100))   # nurse, receptionist, admin
    phone           = Column(String(20))
    email           = Column(String(200), unique=True)
    is_active       = Column(Boolean, default=True)


class UserAuth(Base):
    __tablename__ = "user_auth"
    __table_args__ = {"schema": "users"}

    auth_id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_ref_id     = Column(UUID(as_uuid=True), nullable=False)  # FK to patient/doctor/staff
    role            = Column(Enum(RoleEnum), nullable=False)
    username        = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(500), nullable=False)
    is_active       = Column(Boolean, default=True)
    refresh_token   = Column(String(500))
