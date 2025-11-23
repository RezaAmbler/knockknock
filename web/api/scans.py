"""Scans API endpoints"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import json

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.scan_run import ScanRun, ScanStatus
from web.models.target import Target
from web.schemas import scan as schemas
from web.jobs.tasks import execute_scan

router = APIRouter()


@router.post("", response_model=schemas.ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: schemas.ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create and enqueue ad-hoc scan"""

    # Validate targets exist
    targets = db.query(Target).filter(Target.id.in_(scan_data.target_ids)).all()
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid targets found"
        )

    # Enforce concurrency limit
    active_scans = db.query(ScanRun).filter(
        ScanRun.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
    ).count()

    if active_scans >= 3:  # TODO: Make configurable
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many concurrent scans ({active_scans}/3)"
        )

    # Create scan run
    config_snapshot = {
        'target_ids': scan_data.target_ids,
        'overrides': scan_data.overrides.dict() if scan_data.overrides else {},
        'email': {
            'send_email': scan_data.send_email,
            'recipients': scan_data.email_recipients,
            'from_address': scan_data.email_from
        }
    }

    scan_run = ScanRun(
        initiated_by_id=current_user.id,
        status=ScanStatus.QUEUED,
        config_snapshot=json.dumps(config_snapshot)
    )

    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    # Enqueue scan
    execute_scan.delay(scan_run.id)

    return scan_run


@router.get("", response_model=schemas.ScanListResponse)
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    status: ScanStatus = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List scans with pagination and filters"""
    query = db.query(ScanRun).order_by(ScanRun.created_at.desc())

    if status:
        query = query.filter(ScanRun.status == status)

    total = query.count()
    scans = query.offset(skip).limit(limit).all()

    return {"total": total, "scans": scans}


@router.get("/{scan_id}", response_model=schemas.ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan details"""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
