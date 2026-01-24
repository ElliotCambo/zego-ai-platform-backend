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
    api_key: Optional[str] = None  # n8n API key (stored in admin portal DB)
    
    class Config:
        from_attributes = True


class N8nPodApiKeyUpdate(BaseModel):
    api_key: Optional[str] = None


class WorkflowResponse(BaseModel):
    id: str  # n8n workflow ID
    name: str
    url: str  # Workflow webhook URL
    container_id: Optional[str] = None  # Pod container ID
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    owner: Optional[str] = None  # Workflow owner/user
    active: bool = False
    pod_name: str  # Which pod this workflow belongs to
    pod_id: int  # Pod ID


class N8nPodCreate(BaseModel):
    name: str  # Department name


# MCP Server Schemas
class MCPServerCreate(BaseModel):
    name: str
    swagger_file: str  # Swagger/OpenAPI file content
    api_url: Optional[str] = None  # URL where the API (defined in swagger) is hosted


class MCPServerUpdate(BaseModel):
    api_url: Optional[str] = None
    swagger_file: Optional[str] = None  # Updated swagger/OpenAPI file content


class MCPServerResponse(BaseModel):
    id: int
    name: str
    url: Optional[str]  # MCP server URL
    api_url: Optional[str]  # API URL where swagger API is hosted
    status: str
    litellm_server_id: Optional[str] = None  # LiteLLM's server_id
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

