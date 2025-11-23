"""Targets API endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.target import Target
from web.schemas import target as schemas

router = APIRouter()


@router.post("", response_model=schemas.TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    target_data: schemas.TargetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new target"""
    target = Target(**target_data.dict())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=schemas.TargetListResponse)
async def list_targets(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all targets"""
    total = db.query(Target).count()
    targets = db.query(Target).offset(skip).limit(limit).all()
    return {"total": total, "targets": targets}


@router.get("/{target_id}", response_model=schemas.TargetResponse)
async def get_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get target by ID"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}", response_model=schemas.TargetResponse)
async def update_target(
    target_id: int,
    target_data: schemas.TargetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    for key, value in target_data.dict(exclude_unset=True).items():
        setattr(target, key, value)

    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete target"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    db.delete(target)
    db.commit()
    return None
