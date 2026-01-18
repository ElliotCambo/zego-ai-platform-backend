"""
Pydantic schemas for Admin Portal API
"""
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime


# User Schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    is_admin: bool = False


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


# N8n Pod Schemas (from pod-spawner)
class N8nPodResponse(BaseModel):
    id: int
    name: str
    department_name: str
    subdomain: str
    url: str
    status: str
    container_id: Optional[str] = None  # Kubernetes pod UID or container ID
    created_at: datetime
    enabled_nodes: Optional[str] = None  # Comma-separated list
    
    class Config:
        from_attributes = True


class N8nPodCreate(BaseModel):
    name: str  # Department name


# MCP Server Schemas
class MCPServerCreate(BaseModel):
    name: str
    swagger_file: str  # Swagger/OpenAPI file content


class MCPServerResponse(BaseModel):
    id: int
    name: str
    url: Optional[str]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# Voice Agent Schemas
class VoiceAgentCreate(BaseModel):
    scenario_name: str
    description: Optional[str] = None
    mcp_endpoints: Optional[List[int]] = None  # List of MCP server IDs
    n8n_instance_id: Optional[int] = None
    auth_needed: bool = False
    auth_config: Optional[Dict[str, Any]] = None


class VoiceAgentResponse(BaseModel):
    id: int
    scenario_name: str
    description: Optional[str]
    mcp_endpoints: Optional[List[int]]
    n8n_instance_id: Optional[int]
    auth_needed: bool
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# Development Agent Schemas
class DevAgentCreate(BaseModel):
    name: str
    description: Optional[str] = None
    repo_urls: List[str]
    cursor_api_key: str


class DevAgentResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    repo_urls: Optional[List[str]]
    url: Optional[str]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

