
from uuid import uuid4
from typing import Optional
from datetime import datetime, timedelta, timezone
import os

import jwt
from pwdlib import PasswordHash

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, String, Text, Boolean
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
)


# --------------------------------------------------
# 1. DATABASE CONFIGURATION
# --------------------------------------------------

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


# --------------------------------------------------
# 2. DATABASE MODELS
# --------------------------------------------------

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


Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# 3. AUTHENTICATION CONFIGURATION
# --------------------------------------------------

# Set PROWORK_SECRET_KEY in your environment for real use.
# The fallback is for local development only.
SECRET_KEY = os.getenv(
    "PROWORK_SECRET_KEY",
    "dev-only-change-this-secret-key-before-deployment",
)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        plain_password, hashed_password
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


# --------------------------------------------------
# 4. FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="ProWork API",
    version="2.0.0",
    description=(
        "Project and Team Management API "
        "with JWT authentication"
    ),
)


# --------------------------------------------------
# 5. REQUEST AND RESPONSE SCHEMAS
# --------------------------------------------------

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


# --------------------------------------------------
# 6. AUTHENTICATION DEPENDENCY
# --------------------------------------------------

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

        # Return a detached copy of the database object.
        db.expunge(user)
        return user

    finally:
        db.close()


# --------------------------------------------------
# 7. ROOT AND HEALTH ENDPOINTS
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "Welcome to ProWork API",
        "version": "2.0.0",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# --------------------------------------------------
# 8. REGISTER USER
# --------------------------------------------------

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


# --------------------------------------------------
# 9. LOGIN AND GET JWT TOKEN
# --------------------------------------------------

@app.post("/auth/login", response_model=TokenResponse)
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

        token = create_access_token(user.id)

        return {
            "access_token": token,
            "token_type": "bearer",
        }

    finally:
        db.close()


# --------------------------------------------------
# 10. GET CURRENT USER
# --------------------------------------------------

@app.get("/auth/me", response_model=UserResponse)
def get_my_profile(
    current_user: UserDB = Depends(get_current_user),
):
    return user_to_schema(current_user)


# --------------------------------------------------
# 11. CREATE PROJECT (AUTHENTICATED)
# --------------------------------------------------

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


# --------------------------------------------------
# 12. GET ALL PROJECTS (AUTHENTICATED)
# --------------------------------------------------

@app.get("/projects", response_model=list[Project])
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


# --------------------------------------------------
# 13. GET ONE PROJECT (AUTHENTICATED)
# --------------------------------------------------

@app.get("/projects/{project_id}", response_model=Project)
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


# --------------------------------------------------
# 14. UPDATE PROJECT (AUTHENTICATED)
# --------------------------------------------------

@app.put("/projects/{project_id}", response_model=Project)
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


# --------------------------------------------------
# 15. DELETE PROJECT (AUTHENTICATED)
# --------------------------------------------------

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
