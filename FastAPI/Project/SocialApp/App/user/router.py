from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from . import schemas, service
from ..core.database import get_db


router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/read/all/", response_model=list[schemas.UserResponse])
def read_users(db: Session = Depends(get_db)):
    return service.read_users(db)

@router.get("/read/one/id/{user_id}", response_model=schemas.UserResponse)
def read_one_user_by_id(user_id: int, db: Session = Depends(get_db)):
    return service.read_one_user_by_id(db, user_id)

@router.get("/read/one/email/{email}", response_model=schemas.UserResponse)
def read_one_user_by_email(email: str, db: Session = Depends(get_db)):
    return service.read_one_user_by_email(db, email)

@router.post(
    "/create/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED
)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return service.create_user(db, user)

@router.put("/update/{user_id}", response_model=schemas.UserResponse)
def update_user(user_id: int, user: schemas.UserCreate, db: Session = Depends(get_db)):
    return service.update_user(db, user_id, user)

@router.delete("/delete/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db)): 
    return service.delete_user(db, user_id)
    
