
from uuid import uuid4
from typing import Optional, Literal
from datetime import datetime, timedelta, timezone
import os

import jwt
from pwdlib import PasswordHash

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Query,
    status,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import (
    create_engine,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
)


# ==================================================
# 1. DATABASE CONFIGURATION
# ==================================================

DATABASE_URL = "sqlite:///./prowork.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


# ==================================================
# 2. DATABASE MODELS
# ==================================================

class UserDB(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )


class ProjectDB(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False
    )


class TaskDB(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True
    )
    title: Mapped[str] = mapped_column(
        String(150), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="todo", nullable=False, index=True
    )
    priority: Mapped[str] = mapped_column(
        String(20), default="medium", nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    due_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# Creates missing tables without deleting existing records.
Base.metadata.create_all(bind=engine)


# ==================================================
# 3. AUTHENTICATION CONFIGURATION
# ==================================================

# Development fallback only. Set PROWORK_SECRET_KEY in production.
SECRET_KEY = os.getenv(
    "PROWORK_SECRET_KEY",
    "dev-only-change-this-secret-key-before-deployment",
)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password,
    )


def create_access_token(user_id: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


# ==================================================
# 4. FASTAPI APPLICATION
# ==================================================

app = FastAPI(
    title="ProWork API",
    version="2.2.0",
    description=(
        "Project and Team Management API with JWT "
        "authentication, task search, sorting, filtering, "
        "and pagination."
    ),
)


# ==================================================
# 5. REQUEST AND RESPONSE SCHEMAS
# ==================================================

class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: Optional[str] = None
    status: str = "active"


class Project(ProjectCreate):
    id: str


class TaskCreate(BaseModel):
    project_id: str
    title: str = Field(min_length=2, max_length=150)
    description: Optional[str] = None
    status: Literal[
        "todo", "in_progress", "completed"
    ] = "todo"
    priority: Literal[
        "low", "medium", "high"
    ] = "medium"
    due_date: Optional[datetime] = None


class TaskUpdate(BaseModel):
    project_id: Optional[str] = None
    title: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=150,
    )
    description: Optional[str] = None
    status: Optional[
        Literal["todo", "in_progress", "completed"]
    ] = None
    priority: Optional[
        Literal["low", "medium", "high"]
    ] = None
    due_date: Optional[datetime] = None


class Task(BaseModel):
    id: str
    project_id: str
    title: str
    description: Optional[str]
    status: str
    priority: str
    created_by: str
    due_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime


# ==================================================
# 6. CONVERT DATABASE MODELS TO API SCHEMAS
# ==================================================

def project_to_schema(project: ProjectDB) -> Project:
    return Project(
        id=project.id,
        name=project.name,
        description=project.description,
        status=project.status,
    )


def user_to_schema(user: UserDB) -> UserResponse:
    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        is_active=user.is_active,
    )


def task_to_schema(task: TaskDB) -> Task:
    return Task(
        id=task.id,
        project_id=task.project_id,
        title=task.title,
        description=task.description,
        status=task.status,
        priority=task.priority,
        created_by=task.created_by,
        due_date=task.due_date,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


# ==================================================
# 7. AUTHENTICATION DEPENDENCY
# ==================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
) -> UserDB:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")

        if not isinstance(user_id, str) or not user_id:
            raise credentials_error

    except jwt.InvalidTokenError:
        raise credentials_error

    db = SessionLocal()

    try:
        user = db.get(UserDB, user_id)

        if user is None or not user.is_active:
            raise credentials_error

        db.expunge(user)
        return user

    finally:
        db.close()


# ==================================================
# 8. ROOT AND HEALTH ENDPOINTS
# ==================================================

@app.get("/")
def root():
    return {
        "message": "Welcome to ProWork API",
        "version": app.version,
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# ==================================================
# 9. REGISTER USER
# ==================================================

@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(user_data: UserCreate):
    db = SessionLocal()

    try:
        email = str(user_data.email).lower()

        existing_user = (
            db.query(UserDB)
            .filter(UserDB.email == email)
            .first()
        )

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="Email is already registered",
            )

        new_user = UserDB(
            id=str(uuid4()),
            name=user_data.name,
            email=email,
            hashed_password=hash_password(
                user_data.password
            ),
            is_active=True,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return user_to_schema(new_user)

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 10. LOGIN AND GET JWT TOKEN
# ==================================================

@app.post(
    "/auth/login",
    response_model=TokenResponse,
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    db = SessionLocal()

    try:
        email = form_data.username.lower()

        user = (
            db.query(UserDB)
            .filter(UserDB.email == email)
            .first()
        )

        if (
            user is None
            or not verify_password(
                form_data.password,
                user.hashed_password,
            )
            or not user.is_active
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {
            "access_token": create_access_token(user.id),
            "token_type": "bearer",
        }

    finally:
        db.close()


# ==================================================
# 11. GET CURRENT USER PROFILE
# ==================================================

@app.get(
    "/auth/me",
    response_model=UserResponse,
)
def get_my_profile(
    current_user: UserDB = Depends(get_current_user),
):
    return user_to_schema(current_user)


# ==================================================
# 12. CREATE PROJECT
# ==================================================

@app.post(
    "/projects",
    response_model=Project,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    project: ProjectCreate,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        new_project = ProjectDB(
            id=str(uuid4()),
            name=project.name,
            description=project.description,
            status=project.status,
        )

        db.add(new_project)
        db.commit()
        db.refresh(new_project)

        return project_to_schema(new_project)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 13. GET ALL PROJECTS
# ==================================================

@app.get(
    "/projects",
    response_model=list[Project],
)
def get_projects(
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        projects = db.query(ProjectDB).all()

        return [
            project_to_schema(project)
            for project in projects
        ]

    finally:
        db.close()


# ==================================================
# 14. GET ONE PROJECT
# ==================================================

@app.get(
    "/projects/{project_id}",
    response_model=Project,
)
def get_project(
    project_id: str,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        project = db.get(ProjectDB, project_id)

        if project is None:
            raise HTTPException(
                status_code=404,
                detail="Project not found",
            )

        return project_to_schema(project)

    finally:
        db.close()


# ==================================================
# 15. UPDATE PROJECT
# ==================================================

@app.put(
    "/projects/{project_id}",
    response_model=Project,
)
def update_project(
    project_id: str,
    updated: ProjectCreate,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        project = db.get(ProjectDB, project_id)

        if project is None:
            raise HTTPException(
                status_code=404,
                detail="Project not found",
            )

        project.name = updated.name
        project.description = updated.description
        project.status = updated.status

        db.commit()
        db.refresh(project)

        return project_to_schema(project)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 16. DELETE PROJECT
# ==================================================

@app.delete("/projects/{project_id}")
def delete_project(
    project_id: str,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        project = db.get(ProjectDB, project_id)

        if project is None:
            raise HTTPException(
                status_code=404,
                detail="Project not found",
            )

        tasks_exist = (
            db.query(TaskDB)
            .filter(TaskDB.project_id == project_id)
            .first()
        )

        if tasks_exist:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Delete or move this project's tasks "
                    "before deleting the project"
                ),
            )

        db.delete(project)
        db.commit()

        return {
            "message": "Project deleted successfully",
            "project_id": project_id,
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 17. CREATE TASK
# ==================================================

@app.post(
    "/tasks",
    response_model=Task,
    status_code=status.HTTP_201_CREATED,
)
def create_task(
    task_data: TaskCreate,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        project = db.get(
            ProjectDB,
            task_data.project_id,
        )

        if project is None:
            raise HTTPException(
                status_code=404,
                detail="Project not found",
            )

        task = TaskDB(
            id=str(uuid4()),
            project_id=task_data.project_id,
            title=task_data.title,
            description=task_data.description,
            status=task_data.status,
            priority=task_data.priority,
            due_date=task_data.due_date,
            created_by=current_user.id,
        )

        db.add(task)
        db.commit()
        db.refresh(task)

        return task_to_schema(task)

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 18. LIST TASKS WITH SEARCH, SORTING, FILTERING
#     AND PAGINATION
# ==================================================

@app.get(
    "/tasks",
    response_model=list[Task],
)
def get_tasks(
    project_id: Optional[str] = None,
    task_status: Optional[
        Literal["todo", "in_progress", "completed"]
    ] = Query(default=None, alias="status"),
    search: Optional[str] = Query(
        default=None,
        min_length=1,
        max_length=150,
    ),
    sort_by: Literal[
        "created_at", "title", "due_date", "priority"
    ] = Query(default="created_at"),
    sort_order: Literal["asc", "desc"] = Query(
        default="desc"
    ),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        query = (
            db.query(TaskDB)
            .filter(TaskDB.created_by == current_user.id)
        )

        # Filter by project
        if project_id:
            query = query.filter(
                TaskDB.project_id == project_id
            )

        # Filter by status
        if task_status:
            query = query.filter(
                TaskDB.status == task_status
            )

        # Search in task title and description
        if search:
            search_text = f"%{search.strip()}%"
            query = query.filter(
                (TaskDB.title.ilike(search_text))
                | (TaskDB.description.ilike(search_text))
            )

        # Whitelist the supported sorting columns
        sort_columns = {
            "created_at": TaskDB.created_at,
            "title": TaskDB.title,
            "due_date": TaskDB.due_date,
            "priority": TaskDB.priority,
        }

        sort_column = sort_columns[sort_by]

        # Apply requested sort direction
        if sort_order == "asc":
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        # Apply pagination after filters and sorting
        tasks = (
            query
            .offset(offset)
            .limit(limit)
            .all()
        )

        return [
            task_to_schema(task)
            for task in tasks
        ]

    finally:
        db.close()


# ==================================================
# 19. GET ONE TASK
# ==================================================

@app.get(
    "/tasks/{task_id}",
    response_model=Task,
)
def get_task(
    task_id: str,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        task = (
            db.query(TaskDB)
            .filter(
                TaskDB.id == task_id,
                TaskDB.created_by == current_user.id,
            )
            .first()
        )

        if task is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found",
            )

        return task_to_schema(task)

    finally:
        db.close()


# ==================================================
# 20. UPDATE TASK
# ==================================================

@app.patch(
    "/tasks/{task_id}",
    response_model=Task,
)
def update_task(
    task_id: str,
    updates: TaskUpdate,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        task = (
            db.query(TaskDB)
            .filter(
                TaskDB.id == task_id,
                TaskDB.created_by == current_user.id,
            )
            .first()
        )

        if task is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found",
            )

        changes = updates.dict(exclude_unset=True)

        if "title" in changes and changes["title"] is None:
            raise HTTPException(
                status_code=422,
                detail="Title cannot be null",
            )

        if "project_id" in changes:
            if not changes["project_id"]:
                raise HTTPException(
                    status_code=422,
                    detail="project_id cannot be empty",
                )

            project = db.get(
                ProjectDB,
                changes["project_id"],
            )

            if project is None:
                raise HTTPException(
                    status_code=404,
                    detail="Project not found",
                )

        for field, value in changes.items():
            setattr(task, field, value)

        task.updated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(task)

        return task_to_schema(task)

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# 21. DELETE TASK
# ==================================================

@app.delete("/tasks/{task_id}")
def delete_task(
    task_id: str,
    current_user: UserDB = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        task = (
            db.query(TaskDB)
            .filter(
                TaskDB.id == task_id,
                TaskDB.created_by == current_user.id,
            )
            .first()
        )

        if task is None:
            raise HTTPException(
                status_code=404,
                detail="Task not found",
            )

        db.delete(task)
        db.commit()

        return {
            "message": "Task deleted successfully",
            "task_id": task_id,
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
