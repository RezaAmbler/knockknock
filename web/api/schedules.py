"""Schedules API endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.schedule import Schedule
from web.schemas import schedule as schemas
from web.jobs.scheduler import calculate_next_run

router = APIRouter()


@router.post("", response_model=schemas.ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    schedule_data: schemas.ScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new schedule"""
    schedule = Schedule(**schedule_data.dict(), created_by_id=current_user.id)

    # Calculate first run
    schedule.next_run_utc = calculate_next_run(schedule)

    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


@router.get("", response_model=list)
async def list_schedules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all schedules"""
    schedules = db.query(Schedule).all()
    return schedules


@router.get("/{schedule_id}", response_model=schemas.ScheduleResponse)
async def get_schedule(
    schedule_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get schedule by ID"""
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.put("/{schedule_id}", response_model=schemas.ScheduleResponse)
async def update_schedule(
    schedule_id: int,
    schedule_data: schemas.ScheduleUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update schedule"""
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    for key, value in schedule_data.dict(exclude_unset=True).items():
        setattr(schedule, key, value)

    # Recalculate next run if schedule changed
    if any(k in schedule_data.dict(exclude_unset=True) for k in ['cron_expression', 'interval_seconds']):
        schedule.next_run_utc = calculate_next_run(schedule)

    db.commit()
    db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete schedule"""
    schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    db.delete(schedule)
    db.commit()
    return None
