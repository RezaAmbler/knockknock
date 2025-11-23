"""Target schemas"""

from pydantic import BaseModel, validator
from datetime import datetime
from typing import Optional, List


class TargetBase(BaseModel):
    friendly_name: str
    ip_address: Optional[str] = None
    dns_name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None

    @validator('ip_address', 'dns_name')
    def validate_address(cls, v, values):
        # At least one of ip_address or dns_name must be provided
        if not v and not values.get('ip_address') and not values.get('dns_name'):
            raise ValueError('Either ip_address or dns_name must be provided')
        return v


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    friendly_name: Optional[str] = None
    ip_address: Optional[str] = None
    dns_name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None


class TargetResponse(TargetBase):
    id: int
    is_valid: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TargetListResponse(BaseModel):
    total: int
    targets: List[TargetResponse]
