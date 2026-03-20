# ============================================================
#  mediflow_db/models/__init__.py
#
#  Python resolves `import mediflow_db.models` to this folder.
#  We load the flat models.py directly using importlib to avoid
#  the circular import that happens with `from mediflow_db.models import X`
# ============================================================

import sys
import os
import importlib.util

# Path to the flat models.py file (one level up from this folder)
_flat_path = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "models.py")
)

# Only load once
_MODULE_KEY = "mediflow_db._flat_models"

if _MODULE_KEY not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_MODULE_KEY, _flat_path)
    _mod  = importlib.util.module_from_spec(_spec)
    sys.modules[_MODULE_KEY] = _mod
    _spec.loader.exec_module(_mod)

_m = sys.modules[_MODULE_KEY]

# ── Enums ─────────────────────────────────────────────────────
RoleEnum               = _m.RoleEnum
UrgencyEnum            = _m.UrgencyEnum
AppointmentTypeEnum    = _m.AppointmentTypeEnum
AppointmentStatusEnum  = _m.AppointmentStatusEnum
QueueStatusEnum        = _m.QueueStatusEnum

# ── ORM: Organization ─────────────────────────────────────────
Hospital               = _m.Hospital
Branch                 = _m.Branch
Department             = _m.Department
Room                   = _m.Room

# ── ORM: Users ────────────────────────────────────────────────
Patient                = _m.Patient
Doctor                 = _m.Doctor
Staff                  = _m.Staff
UserAuth               = _m.UserAuth

# ── ORM: Scheduling ───────────────────────────────────────────
TimeSlot               = _m.TimeSlot
Appointment            = _m.Appointment
SlotBlock              = _m.SlotBlock
Recurrence             = _m.Recurrence

# ── ORM: Queue ────────────────────────────────────────────────
QueueEntry             = _m.QueueEntry
PriorityScore          = _m.PriorityScore
EmergencyOverride      = _m.EmergencyOverride
WaitTimeEstimate       = _m.WaitTimeEstimate

# ── ORM: Analytics ────────────────────────────────────────────
AppointmentLog         = _m.AppointmentLog
PeakHourStat           = _m.PeakHourStat
DoctorPerformance      = _m.DoctorPerformance
BranchLoadStat         = _m.BranchLoadStat
WaitTimeTrend          = _m.WaitTimeTrend

# ── Pydantic: Organization ────────────────────────────────────
HospitalData           = _m.HospitalData
HospitalResponse       = _m.HospitalResponse
BranchData             = _m.BranchData
BranchResponse         = _m.BranchResponse
DepartmentData         = _m.DepartmentData
DepartmentResponse     = _m.DepartmentResponse

# ── Pydantic: Users ───────────────────────────────────────────
PatientData            = _m.PatientData
PatientResponse        = _m.PatientResponse
DoctorData             = _m.DoctorData
DoctorResponse         = _m.DoctorResponse
UserAuthData           = _m.UserAuthData
UserAuthResponse       = _m.UserAuthResponse
LoginResponse          = _m.LoginResponse

# ── Pydantic: Scheduling ──────────────────────────────────────
AppointmentData        = _m.AppointmentData
AppointmentResponse    = _m.AppointmentResponse
TimeSlotData           = _m.TimeSlotData
TimeSlotResponse       = _m.TimeSlotResponse

# ── Pydantic: Queue ───────────────────────────────────────────
QueueEntryResponse      = _m.QueueEntryResponse
PriorityScoreResponse   = _m.PriorityScoreResponse
EmergencyOverrideData   = _m.EmergencyOverrideData
EmergencyOverrideResponse = _m.EmergencyOverrideResponse
