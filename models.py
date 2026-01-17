"""
Database models for Admin Portal
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    """User model for admin portal"""
    __tablename__ = "admin_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)  # Hashed password
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class MCPServer(Base):
    """MCP Server model"""
    __tablename__ = "mcp_servers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    url = Column(String(500), nullable=True)  # URL of the MCP server
    swagger_file = Column(Text, nullable=True)  # Original swagger file content
    mcp_config = Column(JSON, nullable=True)  # Converted MCP configuration
    status = Column(String(50), default="stopped")  # stopped, running, error
    pod_name = Column(String(200), nullable=True)  # Kubernetes pod name
    service_name = Column(String(200), nullable=True)  # Kubernetes service name
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class VoiceAgent(Base):
    """Voice Agent scenario model"""
    __tablename__ = "voice_agents"
    
    id = Column(Integer, primary_key=True, index=True)
    scenario_name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    mcp_endpoints = Column(JSON, nullable=True)  # List of MCP server IDs/names
    n8n_instance_id = Column(Integer, nullable=True)  # Reference to n8n pod (no FK - pods in different DB)
    auth_needed = Column(Boolean, default=False)
    auth_config = Column(JSON, nullable=True)  # Authentication configuration
    status = Column(String(50), default="inactive")  # inactive, active, error
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class DevelopmentAgent(Base):
    """Development Agent model"""
    __tablename__ = "dev_agents"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    repo_urls = Column(JSON, nullable=True)  # List of repository URLs
    cursor_api_key = Column(String(255), nullable=True)  # Cursor API key
    url = Column(String(500), nullable=True)  # Agent endpoint URL
    status = Column(String(50), default="stopped")  # stopped, running, error
    pod_name = Column(String(200), nullable=True)  # Kubernetes pod name
    service_name = Column(String(200), nullable=True)  # Kubernetes service name
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

