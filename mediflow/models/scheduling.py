# ============================================================
#  crimson/mediflow_db/models/scheduling.py
#  Schema: SCHEDULING
#  Tables: appointments, time_slots, slot_blocks, recurrences
# ============================================================

import uuid
import enum
from sqlalchemy import Column, String, Boolean, Integer, Float, ForeignKey, DateTime, Date, Time, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from mediflow_db.database import Base


class UrgencyEnum(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"


class AppointmentTypeEnum(str, enum.Enum):
    consultation = "consultation"
    surgery      = "surgery"
    follow_up    = "follow_up"
    emergency    = "emergency"


class AppointmentStatusEnum(str, enum.Enum):
    scheduled   = "scheduled"
    in_progress = "in_progress"
    completed   = "completed"
    cancelled   = "cancelled"
    no_show     = "no_show"


class Appointment(Base):
    __tablename__ = "appointments"
    __table_args__ = {"schema": "scheduling"}

    appointment_id      = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id          = Column(UUID(as_uuid=True), ForeignKey("users.patients.patient_id"), nullable=False)
    doctor_id           = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"), nullable=False)
    branch_id           = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"), nullable=False)
    slot_id             = Column(UUID(as_uuid=True), ForeignKey("scheduling.time_slots.slot_id"))
    urgency_level       = Column(Enum(UrgencyEnum), nullable=False)
    appointment_type    = Column(Enum(AppointmentTypeEnum), nullable=False)
    status              = Column(Enum(AppointmentStatusEnum), default=AppointmentStatusEnum.scheduled)
    booked_at           = Column(DateTime)
    scheduled_time      = Column(DateTime, nullable=False)
    actual_start_time   = Column(DateTime)
    actual_end_time     = Column(DateTime)
    notes               = Column(Text)

    # Relationships
    patient             = relationship("Patient", back_populates="appointments")
    doctor              = relationship("Doctor", back_populates="appointments")
    slot                = relationship("TimeSlot", back_populates="appointments")
    queue_entry         = relationship("QueueEntry", back_populates="appointment", uselist=False)


class TimeSlot(Base):
    __tablename__ = "time_slots"
    __table_args__ = {"schema": "scheduling"}

    slot_id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doctor_id       = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"), nullable=False)
    branch_id       = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"), nullable=False)
    date            = Column(Date, nullable=False)
    start_time      = Column(Time, nullable=False)
    end_time        = Column(Time, nullable=False)
    is_available    = Column(Boolean, default=True)
    is_peak_hour    = Column(Boolean, default=False)
    load_factor     = Column(Float, default=0.0)
    capacity        = Column(Integer, default=1)
    booked_count    = Column(Integer, default=0)

    # Relationships
    doctor          = relationship("Doctor", back_populates="time_slots")
    appointments    = relationship("Appointment", back_populates="slot")


class SlotBlock(Base):
    __tablename__ = "slot_blocks"
    __table_args__ = {"schema": "scheduling"}

    block_id        = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doctor_id       = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"))
    branch_id       = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"))
    start_datetime  = Column(DateTime, nullable=False)
    end_datetime    = Column(DateTime, nullable=False)
    reason          = Column(String(300))   # holiday, break, leave


class Recurrence(Base):
    __tablename__ = "recurrences"
    __table_args__ = {"schema": "scheduling"}

    recurrence_id   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    patient_id      = Column(UUID(as_uuid=True), ForeignKey("users.patients.patient_id"))
    doctor_id       = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"))
    frequency       = Column(String(50))    # weekly, biweekly, monthly
    day_of_week     = Column(Integer)       # 0=Monday ... 6=Sunday
    preferred_time  = Column(Time)
    is_active       = Column(Boolean, default=True)
