from sqlalchemy.orm import Session
from sqlalchemy import text
from .schemas import UserCreate, UserResponse
from ..core.security import hash_password


def read_users(db: Session) -> list[UserResponse]:
    """Read all users using raw SQL"""
    result = db.execute(text("SELECT id, email, created_at, updated_at FROM users"))
    rows = result.mappings().all()
    return [UserResponse.model_validate(dict(row)) for row in rows]


def read_one_user_by_id(db: Session, user_id: int) -> UserResponse | None:
    """Read a single user by ID using raw SQL"""
    result = db.execute(
        text("SELECT * FROM users WHERE id = :id"), {"id": user_id}
    )
    row = result.mappings().first()
    return UserResponse.model_validate(dict(row)) if row else None

def read_one_user_by_email(db: Session, email: str) -> UserResponse | None:
    """Read a single user by email using raw SQL"""
    result = db.execute(
        text("SELECT * FROM users WHERE email = :email"), {"email": email}
    )
    row = result.mappings().first()
    return UserResponse.model_validate(dict(row)) if row else None


def create_user(db: Session, user_data: UserCreate) -> UserResponse:
    """Create a new user using raw SQL with RETURNING"""
    result = db.execute(
        text(
            "INSERT INTO users (email, password_hash) "
            "VALUES (:email, :password_hash) "
            "RETURNING id, email, created_at, updated_at"
        ),
        {"email": user_data.email, "password_hash": hash_password(user_data.password)},
    )
    db.commit()
    row = result.mappings().one()
    return UserResponse.model_validate(dict(row))

def update_user(db: Session, user_id: int, user_data: UserCreate) -> UserResponse | None:
    """Update an existing user using raw SQL with RETURNING"""
    result = db.execute(
        text(
            "UPDATE users SET email = :email, password_hash = :password_hash, updated_at = NOW() " 
            "WHERE id = :id "
            "RETURNING id, email, created_at, updated_at"
        ),
        {"id": user_id, "email": user_data.email, "password_hash": hash_password(user_data.password)},
    )
    db.commit()
    row = result.mappings().first()
    return UserResponse.model_validate(dict(row)) if row else None

def delete_user(db: Session, user_id: int) -> None:
    """Delete a user by ID using raw SQL"""
    
    result = db.execute(
        text("DELETE FROM users WHERE id = :id RETURNING id"), {"id": user_id}
    )
    db.commit()
    if result.rowcount == 0:
        raise Exception(f"User with ID {user_id} not found")
