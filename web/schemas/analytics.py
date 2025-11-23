"""Analytics schemas"""

from pydantic import BaseModel
from typing import List


class DashboardStats(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    success_rate: float


class ChartData(BaseModel):
    labels: List[str]
    data: List[int]
