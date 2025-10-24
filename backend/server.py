from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production-' + str(uuid.uuid4()))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ============ MODELS ============

class Admin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    username: str
    password_hash: str
    role: str = "admin"

class Student(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    class_name: str
    username: str
    password_hash: str
    role: str = "student"  # "student" or "class_rep"
    created_by: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Timetable(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    class_name: str
    day: str  # Monday, Tuesday, etc.
    period: int  # 1-10
    subject: str
    created_by: Optional[str] = None

class Homework(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    description: str
    due_date: str  # ISO date string
    class_name: str
    created_by: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Exam(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    date: str  # ISO date string
    syllabus: str
    type: str  # Midterm, Final, Quiz, etc.
    class_name: str
    created_by: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class HomeworkStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    student_id: str
    homework_id: str
    status: str  # "completed" or "pending"

class Notice(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    message: str
    class_name: str
    date_posted: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str

# ============ INPUT MODELS ============

class LoginRequest(BaseModel):
    username: str
    password: str

class StudentCreate(BaseModel):
    name: str
    class_name: str
    username: str
    password: str
    role: str = "student"

class StudentRoleUpdate(BaseModel):
    role: str

class TimetableCreate(BaseModel):
    class_name: str
    day: str
    period: int
    subject: str

class HomeworkCreate(BaseModel):
    subject: str
    description: str
    due_date: str
    class_name: str

class HomeworkUpdate(BaseModel):
    subject: Optional[str] = None
    description: Optional[str] = None
    due_date: Optional[str] = None

class ExamCreate(BaseModel):
    subject: str
    date: str
    syllabus: str
    type: str
    class_name: str

class ExamUpdate(BaseModel):
    subject: Optional[str] = None
    date: Optional[str] = None
    syllabus: Optional[str] = None
    type: Optional[str] = None

class HomeworkStatusUpdate(BaseModel):
    status: str

class NoticeCreate(BaseModel):
    title: str
    message: str
    class_name: str

# ============ AUTH UTILITIES ============

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        user_type = payload.get("type")  # "admin" or "student"
        role = payload.get("role")
        class_name = payload.get("class_name")
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return {
            "id": user_id,
            "type": user_type,
            "role": role,
            "class_name": class_name
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["type"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

async def require_class_rep(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "class_rep":
        raise HTTPException(status_code=403, detail="Class Representative access required")
    return current_user

# ============ AUTH ENDPOINTS ============

@api_router.post("/auth/login")
async def login(request: LoginRequest):
    # Try admin login first
    admin = await db.admins.find_one({"username": request.username})
    if admin:
        if verify_password(request.password, admin["password_hash"]):
            token = create_access_token({
                "sub": admin["id"],
                "type": "admin",
                "role": "admin",
                "username": admin["username"]
            })
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": admin["id"],
                    "name": admin["name"],
                    "username": admin["username"],
                    "type": "admin",
                    "role": "admin"
                }
            }
    
    # Try student login
    student = await db.students.find_one({"username": request.username})
    if student:
        if verify_password(request.password, student["password_hash"]):
            token = create_access_token({
                "sub": student["id"],
                "type": "student",
                "role": student["role"],
                "class_name": student["class_name"],
                "username": student["username"]
            })
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": student["id"],
                    "name": student["name"],
                    "username": student["username"],
                    "type": "student",
                    "role": student["role"],
                    "class_name": student["class_name"]
                }
            }
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@api_router.get("/auth/session")
async def get_session(current_user: dict = Depends(get_current_user)):
    # Return user details from token
    if current_user["type"] == "admin":
        admin = await db.admins.find_one({"id": current_user["id"]}, {"_id": 0, "password_hash": 0})
        if admin:
            return {"user": {**admin, "type": "admin"}}
    else:
        student = await db.students.find_one({"id": current_user["id"]}, {"_id": 0, "password_hash": 0})
        if student:
            return {"user": {**student, "type": "student"}}
    
    raise HTTPException(status_code=401, detail="User not found")

@api_router.post("/auth/logout")
async def logout():
    return {"message": "Logged out successfully"}

# ============ ADMIN ENDPOINTS ============

@api_router.post("/admin/students", response_model=Student)
async def create_student(student_data: StudentCreate, current_user: dict = Depends(require_admin)):
    # Check if username already exists
    existing = await db.students.find_one({"username": student_data.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    student = Student(
        name=student_data.name,
        class_name=student_data.class_name,
        username=student_data.username,
        password_hash=hash_password(student_data.password),
        role=student_data.role,
        created_by=current_user["id"]
    )
    
    doc = student.model_dump()
    await db.students.insert_one(doc)
    return student

@api_router.get("/admin/students", response_model=List[Student])
async def get_all_students(current_user: dict = Depends(require_admin)):
    students = await db.students.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return students

@api_router.put("/admin/students/{student_id}/role")
async def update_student_role(student_id: str, role_data: StudentRoleUpdate, current_user: dict = Depends(require_admin)):
    result = await db.students.update_one(
        {"id": student_id},
        {"$set": {"role": role_data.role}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Student not found")
    return {"message": "Role updated successfully"}

@api_router.post("/admin/timetable", response_model=Timetable)
async def create_timetable_entry(timetable_data: TimetableCreate, current_user: dict = Depends(require_admin)):
    # Check if entry already exists for this class, day, and period
    existing = await db.timetable.find_one({
        "class_name": timetable_data.class_name,
        "day": timetable_data.day,
        "period": timetable_data.period
    })
    
    if existing:
        # Update existing entry
        await db.timetable.update_one(
            {"id": existing["id"]},
            {"$set": {"subject": timetable_data.subject}}
        )
        existing["subject"] = timetable_data.subject
        return Timetable(**existing)
    
    timetable = Timetable(
        class_name=timetable_data.class_name,
        day=timetable_data.day,
        period=timetable_data.period,
        subject=timetable_data.subject,
        created_by=current_user["id"]
    )
    
    doc = timetable.model_dump()
    await db.timetable.insert_one(doc)
    return timetable

@api_router.get("/admin/timetable")
async def get_admin_timetable(class_name: Optional[str] = None, current_user: dict = Depends(require_admin)):
    query = {}
    if class_name:
        query["class_name"] = class_name
    
    timetable = await db.timetable.find(query, {"_id": 0}).to_list(1000)
    return timetable

@api_router.delete("/admin/timetable/{timetable_id}")
async def delete_timetable_entry(timetable_id: str, current_user: dict = Depends(require_admin)):
    result = await db.timetable.delete_one({"id": timetable_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Timetable entry not found")
    return {"message": "Timetable entry deleted successfully"}

# ============ HOMEWORK ENDPOINTS ============

@api_router.post("/homework", response_model=Homework)
async def create_homework(homework_data: HomeworkCreate, current_user: dict = Depends(require_class_rep)):
    homework = Homework(
        subject=homework_data.subject,
        description=homework_data.description,
        due_date=homework_data.due_date,
        class_name=homework_data.class_name,
        created_by=current_user["id"]
    )
    
    doc = homework.model_dump()
    await db.homework.insert_one(doc)
    return homework

@api_router.get("/homework")
async def get_homework(current_user: dict = Depends(get_current_user)):
    class_name = current_user.get("class_name")
    if not class_name:
        return []
    
    homework_list = await db.homework.find({"class_name": class_name}, {"_id": 0}).to_list(1000)
    
    # Get homework status for current student
    if current_user["type"] == "student":
        student_id = current_user["id"]
        for hw in homework_list:
            status_doc = await db.homework_status.find_one({
                "student_id": student_id,
                "homework_id": hw["id"]
            })
            hw["status"] = status_doc["status"] if status_doc else "pending"
    
    # Calculate smart reminders based on timetable
    today = datetime.now(timezone.utc)
    tomorrow = today + timedelta(days=1)
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    tomorrow_day = day_names[tomorrow.weekday()]
    
    # Get tomorrow's timetable
    tomorrow_classes = await db.timetable.find({
        "class_name": class_name,
        "day": tomorrow_day
    }, {"_id": 0}).to_list(100)
    
    tomorrow_subjects = [entry["subject"] for entry in tomorrow_classes]
    
    # Add reminder flag for homework due and class tomorrow
    for hw in homework_list:
        hw["reminder"] = hw["subject"] in tomorrow_subjects and hw.get("status", "pending") == "pending"
    
    return homework_list

@api_router.put("/homework/{homework_id}")
async def update_homework(homework_id: str, homework_data: HomeworkUpdate, current_user: dict = Depends(require_class_rep)):
    update_data = {k: v for k, v in homework_data.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.homework.update_one(
        {"id": homework_id},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Homework not found")
    return {"message": "Homework updated successfully"}

@api_router.delete("/homework/{homework_id}")
async def delete_homework(homework_id: str, current_user: dict = Depends(require_class_rep)):
    result = await db.homework.delete_one({"id": homework_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Homework not found")
    
    # Also delete all homework status entries
    await db.homework_status.delete_many({"homework_id": homework_id})
    return {"message": "Homework deleted successfully"}

@api_router.post("/homework/{homework_id}/status")
async def update_homework_status(homework_id: str, status_data: HomeworkStatusUpdate, current_user: dict = Depends(get_current_user)):
    if current_user["type"] != "student":
        raise HTTPException(status_code=403, detail="Only students can update homework status")
    
    student_id = current_user["id"]
    
    # Check if homework exists
    homework = await db.homework.find_one({"id": homework_id})
    if not homework:
        raise HTTPException(status_code=404, detail="Homework not found")
    
    # Upsert homework status
    await db.homework_status.update_one(
        {"student_id": student_id, "homework_id": homework_id},
        {"$set": {"student_id": student_id, "homework_id": homework_id, "status": status_data.status}},
        upsert=True
    )
    
    return {"message": "Homework status updated successfully"}

# ============ EXAM ENDPOINTS ============

@api_router.post("/exams", response_model=Exam)
async def create_exam(exam_data: ExamCreate, current_user: dict = Depends(require_class_rep)):
    exam = Exam(
        subject=exam_data.subject,
        date=exam_data.date,
        syllabus=exam_data.syllabus,
        type=exam_data.type,
        class_name=exam_data.class_name,
        created_by=current_user["id"]
    )
    
    doc = exam.model_dump()
    await db.exams.insert_one(doc)
    return exam

@api_router.get("/exams")
async def get_exams(current_user: dict = Depends(get_current_user)):
    class_name = current_user.get("class_name")
    if not class_name:
        return []
    
    exams = await db.exams.find({"class_name": class_name}, {"_id": 0}).to_list(1000)
    
    # Calculate days remaining and color code
    today = datetime.now(timezone.utc).date()
    for exam in exams:
        exam_date = datetime.fromisoformat(exam["date"]).date()
        days_remaining = (exam_date - today).days
        exam["days_remaining"] = days_remaining
        
        # Color coding
        if days_remaining < 0:
            exam["urgency_color"] = "gray"
        elif days_remaining <= 1:
            exam["urgency_color"] = "red"
        elif days_remaining <= 2:
            exam["urgency_color"] = "orange"
        elif days_remaining <= 6:
            exam["urgency_color"] = "yellow"
        else:
            exam["urgency_color"] = "green"
    
    return exams

@api_router.put("/exams/{exam_id}")
async def update_exam(exam_id: str, exam_data: ExamUpdate, current_user: dict = Depends(require_class_rep)):
    update_data = {k: v for k, v in exam_data.model_dump().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.exams.update_one(
        {"id": exam_id},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Exam not found")
    return {"message": "Exam updated successfully"}

@api_router.delete("/exams/{exam_id}")
async def delete_exam(exam_id: str, current_user: dict = Depends(require_class_rep)):
    result = await db.exams.delete_one({"id": exam_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Exam not found")
    return {"message": "Exam deleted successfully"}

# ============ NOTICE ENDPOINTS ============

@api_router.post("/notices", response_model=Notice)
async def create_notice(notice_data: NoticeCreate, current_user: dict = Depends(require_class_rep)):
    notice = Notice(
        title=notice_data.title,
        message=notice_data.message,
        class_name=notice_data.class_name,
        created_by=current_user["id"]
    )
    
    doc = notice.model_dump()
    await db.notices.insert_one(doc)
    return notice

@api_router.get("/notices")
async def get_notices(current_user: dict = Depends(get_current_user)):
    class_name = current_user.get("class_name")
    if not class_name:
        return []
    
    notices = await db.notices.find({"class_name": class_name}, {"_id": 0}).sort("date_posted", -1).to_list(1000)
    return notices

@api_router.delete("/notices/{notice_id}")
async def delete_notice(notice_id: str, current_user: dict = Depends(require_class_rep)):
    result = await db.notices.delete_one({"id": notice_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Notice not found")
    return {"message": "Notice deleted successfully"}

# ============ PROGRESS ENDPOINTS ============

@api_router.get("/progress")
async def get_student_progress(current_user: dict = Depends(get_current_user)):
    if current_user["type"] != "student":
        raise HTTPException(status_code=403, detail="Only students can view their progress")
    
    student_id = current_user["id"]
    class_name = current_user["class_name"]
    
    # Get all homework for this class
    all_homework = await db.homework.find({"class_name": class_name}, {"_id": 0}).to_list(1000)
    
    if not all_homework:
        return {
            "overall_progress": 0,
            "total_homework": 0,
            "completed_homework": 0,
            "subject_progress": []
        }
    
    # Get student's homework status
    completed_count = 0
    subject_stats = {}
    
    for hw in all_homework:
        subject = hw["subject"]
        if subject not in subject_stats:
            subject_stats[subject] = {"total": 0, "completed": 0}
        subject_stats[subject]["total"] += 1
        
        status_doc = await db.homework_status.find_one({
            "student_id": student_id,
            "homework_id": hw["id"]
        })
        
        if status_doc and status_doc["status"] == "completed":
            completed_count += 1
            subject_stats[subject]["completed"] += 1
    
    overall_progress = (completed_count / len(all_homework)) * 100 if all_homework else 0
    
    subject_progress = [
        {
            "subject": subject,
            "total": stats["total"],
            "completed": stats["completed"],
            "progress": (stats["completed"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        }
        for subject, stats in subject_stats.items()
    ]
    
    return {
        "overall_progress": round(overall_progress, 1),
        "total_homework": len(all_homework),
        "completed_homework": completed_count,
        "subject_progress": subject_progress
    }

@api_router.get("/progress/class")
async def get_class_progress(current_user: dict = Depends(require_class_rep)):
    class_name = current_user["class_name"]
    
    # Get all students in class
    students = await db.students.find({"class_name": class_name}, {"_id": 0, "password_hash": 0}).to_list(1000)
    
    # Get all homework for class
    all_homework = await db.homework.find({"class_name": class_name}, {"_id": 0}).to_list(1000)
    
    if not all_homework:
        return []
    
    result = []
    for student in students:
        completed_count = 0
        for hw in all_homework:
            status_doc = await db.homework_status.find_one({
                "student_id": student["id"],
                "homework_id": hw["id"]
            })
            if status_doc and status_doc["status"] == "completed":
                completed_count += 1
        
        progress = (completed_count / len(all_homework)) * 100 if all_homework else 0
        result.append({
            "student_id": student["id"],
            "student_name": student["name"],
            "total_homework": len(all_homework),
            "completed_homework": completed_count,
            "progress": round(progress, 1)
        })
    
    return result

# ============ TIMETABLE ENDPOINTS ============

@api_router.get("/timetable")
async def get_timetable(current_user: dict = Depends(get_current_user)):
    class_name = current_user.get("class_name")
    if not class_name:
        return []
    
    timetable = await db.timetable.find({"class_name": class_name}, {"_id": 0}).to_list(1000)
    return timetable

# ============ INITIALIZATION ============

@app.on_event("startup")
async def startup_event():
    # Create default admin if not exists
    admin = await db.admins.find_one({"username": "admin"})
    if not admin:
        default_admin = Admin(
            name="Administrator",
            username="admin",
            password_hash=hash_password("admin123"),
            role="admin"
        )
        await db.admins.insert_one(default_admin.model_dump())
        logger.info("Default admin created: username=admin, password=admin123")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()