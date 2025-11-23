"""Target list schemas"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class TargetListBase(BaseModel):
    name: str
    description: Optional[str] = None


class TargetListCreate(TargetListBase):
    target_ids: List[int] = []


class TargetListUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_ids: Optional[List[int]] = None


class TargetListResponse(TargetListBase):
    id: int
    created_at: datetime
    updated_at: datetime
    target_count: Optional[int] = 0

    class Config:
        from_attributes = True


class TargetListListResponse(BaseModel):
    total: int
    target_lists: List[TargetListResponse]
