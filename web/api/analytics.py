"""Analytics API endpoints"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.scan_run import ScanRun, ScanStatus
from web.schemas import analytics as schemas

router = APIRouter()


@router.get("/dashboard", response_model=schemas.DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""

    total_scans = db.query(ScanRun).count()
    completed = db.query(ScanRun).filter(ScanRun.status == ScanStatus.SUCCESS).count()
    failed = db.query(ScanRun).filter(ScanRun.status == ScanStatus.ERROR).count()
    running = db.query(ScanRun).filter(ScanRun.status == ScanStatus.RUNNING).count()

    success_rate = (completed / total_scans * 100) if total_scans > 0 else 0

    return {
        'total_scans': total_scans,
        'completed_scans': completed,
        'failed_scans': failed,
        'running_scans': running,
        'success_rate': round(success_rate, 1)
    }


@router.get("/scans-over-time", response_model=schemas.ChartData)
async def get_scans_over_time(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan count grouped by date"""

    start_date = datetime.utcnow() - timedelta(days=days)

    results = db.query(
        func.date(ScanRun.created_at).label('date'),
        func.count(ScanRun.id).label('count')
    ).filter(
        ScanRun.created_at >= start_date
    ).group_by(
        func.date(ScanRun.created_at)
    ).order_by('date').all()

    return {
        'labels': [str(r.date) for r in results],
        'data': [r.count for r in results]
    }
