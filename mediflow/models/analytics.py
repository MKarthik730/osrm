# ============================================================
#  crimson/mediflow_db/models/analytics.py
#  Schema: ANALYTICS
#  Tables: appointment_logs, peak_hour_stats, doctor_performance,
#          branch_load_stats, wait_time_trends
# ============================================================

import uuid
from sqlalchemy import Column, String, Integer, Float, ForeignKey, DateTime, Date, Enum
from sqlalchemy.dialects.postgresql import UUID
from mediflow_db.database import Base
from mediflow_db.models.scheduling import UrgencyEnum, AppointmentTypeEnum, AppointmentStatusEnum


class AppointmentLog(Base):
    """
    Immutable append-only audit trail of every appointment event.
    Never updated — only inserted.
    """
    __tablename__ = "appointment_logs"
    __table_args__ = {"schema": "analytics"}

    log_id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    appointment_id      = Column(UUID(as_uuid=True), nullable=False)
    patient_id          = Column(UUID(as_uuid=True), nullable=False)
    doctor_id           = Column(UUID(as_uuid=True), nullable=False)
    branch_id           = Column(UUID(as_uuid=True), nullable=False)
    urgency_level       = Column(Enum(UrgencyEnum))
    appointment_type    = Column(Enum(AppointmentTypeEnum))
    status              = Column(Enum(AppointmentStatusEnum))
    scheduled_time      = Column(DateTime)
    actual_start_time   = Column(DateTime)
    actual_end_time     = Column(DateTime)
    wait_time_mins      = Column(Float)     # actual wait experienced
    consult_duration_mins = Column(Float)
    logged_at           = Column(DateTime)


class PeakHourStat(Base):
    """
    Aggregated appointment demand per hour per day.
    Powers the heatmap and Holt-Winters forecast.
    """
    __tablename__ = "peak_hour_stats"
    __table_args__ = {"schema": "analytics"}

    stat_id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    branch_id           = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"))
    day_of_week         = Column(Integer)   # 0=Monday ... 6=Sunday
    hour_of_day         = Column(Integer)   # 0–23
    avg_appointments    = Column(Float)
    max_appointments    = Column(Integer)
    avg_wait_mins       = Column(Float)
    recorded_on         = Column(Date)


class DoctorPerformance(Base):
    """
    Tracks per-doctor throughput and consultation metrics.
    """
    __tablename__ = "doctor_performance"
    __table_args__ = {"schema": "analytics"}

    perf_id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doctor_id           = Column(UUID(as_uuid=True), ForeignKey("users.doctors.doctor_id"))
    date                = Column(Date)
    total_appointments  = Column(Integer, default=0)
    completed_count     = Column(Integer, default=0)
    no_show_count       = Column(Integer, default=0)
    avg_consult_mins    = Column(Float)
    avg_wait_mins       = Column(Float)
    utilization_pct     = Column(Float)     # % of available slots used


class BranchLoadStat(Base):
    """
    Time-series load utilization per branch.
    Used for cross-branch routing decisions.
    """
    __tablename__ = "branch_load_stats"
    __table_args__ = {"schema": "analytics"}

    load_id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    branch_id           = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"))
    recorded_at         = Column(DateTime)
    active_appointments = Column(Integer)
    queue_depth         = Column(Integer)
    utilization_pct     = Column(Float)     # current_load / total_capacity
    overflow_redirects  = Column(Integer, default=0)  # patients sent to other branches


class WaitTimeTrend(Base):
    """
    Historical wait time per department — feeds dashboard trend chart.
    """
    __tablename__ = "wait_time_trends"
    __table_args__ = {"schema": "analytics"}

    trend_id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    department_id       = Column(UUID(as_uuid=True), ForeignKey("organization.departments.department_id"))
    branch_id           = Column(UUID(as_uuid=True), ForeignKey("organization.branches.branch_id"))
    date                = Column(Date)
    hour_of_day         = Column(Integer)
    avg_wait_mins       = Column(Float)
    min_wait_mins       = Column(Float)
    max_wait_mins       = Column(Float)
    sample_count        = Column(Integer)
