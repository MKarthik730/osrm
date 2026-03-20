# ============================================================
#  crimson/mediflow_db/models/queue.py
#  Schema: QUEUE
#  Tables: queue_entries, priority_scores, emergency_overrides,
#          wait_time_estimates
# ============================================================

import uuid
import enum
from sqlalchemy import Column, String, Boolean, Integer, Float, ForeignKey, DateTime, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from mediflow_db.database import Base


class QueueStatusEnum(str, enum.Enum):
    waiting  = "waiting"
    called   = "called"
    in_room  = "in_room"
    done     = "done"
    skipped  = "skipped"


class QueueEntry(Base):
    __tablename__ = "queue_entries"
    __table_args__ = {"schema": "queue"}

    queue_id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    appointment_id      = Column(UUID(as_uuid=True), ForeignKey("scheduling.appointments.appointment_id"), nullable=False)
    branch_id           = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"), nullable=False)
    doctor_id           = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"), nullable=False)
    position            = Column(Integer, nullable=False)
    entered_queue_at    = Column(DateTime, nullable=False)
    estimated_wait_mins = Column(Integer)
    is_emergency        = Column(Boolean, default=False)
    override_reason     = Column(Text)
    status              = Column(Enum(QueueStatusEnum), default=QueueStatusEnum.waiting)

    # Relationships
    appointment         = relationship("Appointment", back_populates="queue_entry")
    priority_score      = relationship("PriorityScore", back_populates="queue_entry", uselist=False)
    wait_estimate       = relationship("WaitTimeEstimate", back_populates="queue_entry", uselist=False)


class PriorityScore(Base):
    __tablename__ = "priority_scores"
    __table_args__ = {"schema": "queue"}

    score_id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    queue_id            = Column(UUID(as_uuid=True), ForeignKey("queue.queue_entries.queue_id"), nullable=False)

    # Weights (stored for audit/transparency)
    urgency_weight      = Column(Float, default=0.50)
    wait_weight         = Column(Float, default=0.30)
    age_weight          = Column(Float, default=0.10)
    type_weight         = Column(Float, default=0.10)

    # Raw component scores
    raw_urgency_score   = Column(Integer)   # critical=100, high=75, medium=50, low=25
    raw_wait_score      = Column(Float)     # grows over time — anti-starvation
    raw_age_score       = Column(Integer)   # elderly/child bump
    raw_type_score      = Column(Integer)   # surgery > consultation > follow_up

    # Computed final
    final_score         = Column(Float, nullable=False)
    computed_at         = Column(DateTime, nullable=False)

    # Relationships
    queue_entry         = relationship("QueueEntry", back_populates="priority_score")


class EmergencyOverride(Base):
    __tablename__ = "emergency_overrides"
    __table_args__ = {"schema": "queue"}

    override_id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    queue_id            = Column(UUID(as_uuid=True), ForeignKey("queue.queue_entries.queue_id"), nullable=False)
    triggered_by        = Column(UUID(as_uuid=True))    # staff_id who triggered
    reason              = Column(Text, nullable=False)
    previous_position   = Column(Integer)
    new_position        = Column(Integer, default=1)
    triggered_at        = Column(DateTime, nullable=False)


class WaitTimeEstimate(Base):
    __tablename__ = "wait_time_estimates"
    __table_args__ = {"schema": "queue"}

    estimate_id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    queue_id            = Column(UUID(as_uuid=True), ForeignKey("queue.queue_entries.queue_id"), nullable=False)
    estimated_wait_mins = Column(Float)
    queue_length        = Column(Integer)       # L in Little's Law
    service_rate        = Column(Float)         # λ — rolling avg completions/min
    calculated_at       = Column(DateTime)

    # Relationships
    queue_entry         = relationship("QueueEntry", back_populates="wait_estimate")
