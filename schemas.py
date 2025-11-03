"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name.
"""

from pydantic import BaseModel, Field
from typing import Optional, List

# Example schemas
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Intrusion Detection related schemas
class Block(BaseModel):
    ip: str = Field(..., description="IP address being blocked")
    reason: Optional[str] = Field(None, description="Reason for blocking")
    source: Optional[str] = Field("manual", description="Origin of the block action")

class Alert(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier")
    time: str = Field(..., description="Human readable time or ISO timestamp")
    src: str = Field(..., description="Source IP or host")
    dest: str = Field(..., description="Destination host:port")
    type: str = Field(..., description="Alert type")
    severity: str = Field(..., description="Low | Medium | High")

class ActionLog(BaseModel):
    action: str = Field(..., description="Action name, e.g., block_ip, export_csv, analyze")
    details: Optional[str] = Field(None, description="Free-form details about the action")
    actor: Optional[str] = Field("system", description="Who performed the action")

class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="Raw logs or alert text for analysis")

class AnalyzeResponse(BaseModel):
    risk: str
    summary: List[str]
