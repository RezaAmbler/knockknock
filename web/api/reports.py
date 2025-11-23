"""Reports API endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pathlib import Path

from web.database import get_db
from web.auth.dependencies import get_current_user
from web.models.user import User
from web.models.scan_run import ScanRun

router = APIRouter()


@router.get("/{scan_id}/html")
async def download_html_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download HTML report for a scan"""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.html_report_path:
        raise HTTPException(status_code=404, detail="HTML report not available")

    report_path = Path(scan.html_report_path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        path=str(report_path),
        filename=f"scan-{scan.run_uuid}.html",
        media_type="text/html"
    )
