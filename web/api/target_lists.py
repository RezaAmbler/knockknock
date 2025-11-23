"""Target Lists API endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.target_list import TargetList, TargetListItem
from web.models.target import Target
from web.schemas import target_list as schemas

router = APIRouter()


@router.post("", response_model=schemas.TargetListResponse, status_code=status.HTTP_201_CREATED)
async def create_target_list(
    list_data: schemas.TargetListCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new target list"""
    target_list = TargetList(name=list_data.name, description=list_data.description)
    db.add(target_list)
    db.flush()

    # Add targets to list
    for target_id in list_data.target_ids:
        item = TargetListItem(target_list_id=target_list.id, target_id=target_id)
        db.add(item)

    db.commit()
    db.refresh(target_list)

    response = schemas.TargetListResponse.from_orm(target_list)
    response.target_count = len(list_data.target_ids)
    return response


@router.get("", response_model=schemas.TargetListListResponse)
async def list_target_lists(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all target lists"""
    total = db.query(TargetList).count()
    target_lists = db.query(TargetList).offset(skip).limit(limit).all()

    results = []
    for tl in target_lists:
        response = schemas.TargetListResponse.from_orm(tl)
        response.target_count = len(tl.items)
        results.append(response)

    return {"total": total, "target_lists": results}


@router.get("/{list_id}", response_model=schemas.TargetListResponse)
async def get_target_list(
    list_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get target list by ID"""
    target_list = db.query(TargetList).filter(TargetList.id == list_id).first()
    if not target_list:
        raise HTTPException(status_code=404, detail="Target list not found")

    response = schemas.TargetListResponse.from_orm(target_list)
    response.target_count = len(target_list.items)
    return response


@router.delete("/{list_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target_list(
    list_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete target list"""
    target_list = db.query(TargetList).filter(TargetList.id == list_id).first()
    if not target_list:
        raise HTTPException(status_code=404, detail="Target list not found")

    db.delete(target_list)
    db.commit()
    return None
