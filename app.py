"""
Zego AI Admin Portal Backend API
"""
import sys
import os
import logging
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Configure logging
os.environ.setdefault("PYTHONUNBUFFERED", "1")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

from database import get_db, init_db
from models import User, MCPServer, VoiceAgent, DevelopmentAgent
from schemas import (
    UserCreate, UserResponse, UserLogin,
    N8nPodResponse, N8nPodCreate,
    MCPServerCreate, MCPServerResponse,
    VoiceAgentCreate, VoiceAgentResponse,
    DevAgentCreate, DevAgentResponse
)

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(
    title="Zego AI Admin Portal API",
    description="Admin portal for managing n8n pods, MCP servers, voice agents, and dev agents",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    logger.info("Admin Portal API started")

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "admin-portal"}


# Authentication helpers
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using bcrypt directly"""
    import bcrypt
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt directly for compatibility"""
    import bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


# Authentication endpoints
@app.post("/api/auth/login", response_model=dict)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    """Login endpoint"""
    user = db.query(User).filter(User.username == user_credentials.username).first()
    if not user or not verify_password(user_credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }


# User management endpoints
@app.get("/api/users", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all users (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    users = db.query(User).all()
    return users


@app.post("/api/users", response_model=UserResponse)
async def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new user (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check if user exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=get_password_hash(user.password),
        is_admin=user.is_admin
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# N8n Pods endpoints
@app.get("/api/n8n-pods", response_model=List[N8nPodResponse])
async def list_n8n_pods(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all n8n pods by querying pod-spawner API"""
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get departments and pods from pod-spawner
            depts_response = await client.get(f"{pod_spawner_url}/api/v1/departments")
            depts_response.raise_for_status()
            departments = depts_response.json()
            
            pods_list = []
            for dept in departments:
                pods_response = await client.get(f"{pod_spawner_url}/api/v1/pods/by-department/{dept['id']}")
                if pods_response.status_code == 200:
                    pods = pods_response.json()
                    for pod in pods:
                        # Get detailed pod status from Kubernetes
                        pod_info = await get_pod_status_and_info(pod.get("container_name", ""))
                        
                        # Determine URL based on environment
                        # In AWS, try to get LoadBalancer hostname from service
                        aws_region = os.getenv("AWS_REGION")
                        url = None
                        
                        if aws_region:
                            # AWS: Try to get LoadBalancer hostname from service
                            try:
                                service_name = pod.get("container_name", f"n8n-{pod['subdomain']}")
                                import httpx
                                k8s_api_url = os.getenv("KUBERNETES_SERVICE_HOST")
                                if k8s_api_url:
                                    # Query Kubernetes API for service LoadBalancer hostname
                                    # For now, fetch from pod-spawner or directly query service
                                    # This will be populated by pod-spawner
                                    pass
                            except Exception:
                                pass
                        
                        # Always try to get LoadBalancer hostname from Kubernetes service
                        try:
                            service_name = pod.get("container_name", f"n8n-{pod['subdomain']}")
                            # Query Kubernetes API for service
                            from kubernetes import client as k8s_client, config as k8s_config
                            try:
                                k8s_config.load_incluster_config()
                            except:
                                k8s_config.load_kube_config()
                            v1 = k8s_client.CoreV1Api()
                            namespace = os.getenv("KUBERNETES_NAMESPACE", "zego-ai-platform")
                            service = v1.read_namespaced_service(
                                name=service_name,
                                namespace=namespace
                            )
                            # Check if service has LoadBalancer hostname
                            if (service.status.load_balancer and 
                                service.status.load_balancer.ingress and 
                                len(service.status.load_balancer.ingress) > 0):
                                lb_hostname = service.status.load_balancer.ingress[0].hostname
                                if lb_hostname:
                                    url = f"http://{lb_hostname}"
                        except Exception as e:
                            logger.debug(f"Could not get LoadBalancer hostname for {service_name}: {e}")
                        
                        # Fallback: Construct URL from domain/env if no LoadBalancer
                        if not url:
                            n8n_base_domain = os.getenv("N8N_BASE_DOMAIN", "localhost")
                            traefik_port = os.getenv("TRAEFIK_NODEPORT", "30080")
                            url = f"http://{pod['subdomain']}.n8n.{n8n_base_domain}:{traefik_port}"
                        
                        pods_list.append({
                            "id": pod["id"],
                            "name": pod["name"],
                            "department_name": dept["name"],
                            "subdomain": pod["subdomain"],
                            "url": url,
                            "status": pod_info.get("status", "unknown"),
                            "container_id": pod_info.get("container_id"),
                            "created_at": pod["created_at"],
                            "enabled_nodes": pod.get("nodes_exclude", "")
                        })
            
            return pods_list
    except Exception as e:
        logger.error(f"Error fetching n8n pods: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/n8n-pods", response_model=dict)
async def create_n8n_pod(
    pod: N8nPodCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new n8n pod using pod-spawner API"""
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # First create department if it doesn't exist
            dept_response = await client.post(
                f"{pod_spawner_url}/api/v1/departments",
                json={"name": pod.name}
            )
            dept_response.raise_for_status()
            department = dept_response.json()
            
            # Generate subdomain from department name
            import re
            subdomain = re.sub(r'[^a-z0-9-]', '', pod.name.lower().replace(' ', '-'))
            
            # Then spawn the pod (n8n type)
            spawn_response = await client.post(
                f"{pod_spawner_url}/api/v1/pods/spawn",
                json={
                    "pod_type": "n8n",
                    "department_id": department["id"],
                    "subdomain": subdomain,
                    "name": pod.name
                }
            )
            spawn_response.raise_for_status()
            result = spawn_response.json()
            
            # Ensure URL includes port number if missing
            if "url" in result and ":30080" not in result.get("url", ""):
                traefik_port = os.getenv("TRAEFIK_NODEPORT", "30080")
                result["url"] = f"{result['url']}:{traefik_port}"
            
            return {
                "message": "Pod created successfully",
                "pod": result
            }
    except httpx.HTTPStatusError as e:
        logger.error(f"Error creating n8n pod: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error creating n8n pod: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/n8n-pods/{pod_id}/status")
async def get_n8n_pod_status(
    pod_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed status of an n8n pod from Kubernetes"""
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get pod info from pod-spawner
            pod_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{pod_id}")
            if pod_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Pod not found")
            
            pod_data = pod_response.json()
            container_name = pod_data.get("container_name", "")
            
            # Get detailed status from Kubernetes
            pod_info = await get_pod_status_and_info(container_name)
            
            return {
                "pod_id": pod_id,
                "container_name": container_name,
                "status": pod_info.get("status"),
                "container_id": pod_info.get("container_id"),
                "ready": pod_info.get("ready"),
                "restart_count": pod_info.get("restart_count"),
                "message": pod_info.get("message"),
                "pod_name": pod_info.get("pod_name")
            }
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error getting pod status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/n8n-pods/{pod_id}")
async def delete_n8n_pod(
    pod_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an n8n pod"""
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Delete the pod directly using pod ID
            delete_response = await client.delete(
                f"{pod_spawner_url}/api/v1/pods/{pod_id}"
            )
            if delete_response.status_code in [200, 204]:
                return {"message": "Pod deleted successfully"}
            elif delete_response.status_code == 404:
                raise HTTPException(status_code=404, detail="Pod not found")
            else:
                raise HTTPException(
                    status_code=delete_response.status_code,
                    detail=delete_response.text
                )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error deleting n8n pod: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def get_pod_status_and_info(pod_name: str) -> dict:
    """Get pod status and detailed info from Kubernetes
    
    Returns:
        dict with keys: status, container_id, ready, restart_count, message
    """
    try:
        from kubernetes import client as k8s_client, config as k8s_config
        from kubernetes.client.rest import ApiException
        
        try:
            k8s_config.load_incluster_config()
        except:
            k8s_config.load_kube_config()
        
        v1 = k8s_client.CoreV1Api()
        namespace = os.getenv("KUBERNETES_NAMESPACE", "zego-ai-platform")
        
        # Try to find pod by name pattern or label
        pods = v1.list_namespaced_pod(namespace=namespace)
        for pod in pods.items:
            # Match by name or container_name in labels
            if (pod_name in pod.metadata.name or 
                pod_name in pod.metadata.labels.get("app", "") or
                pod_name in pod.metadata.labels.get("container_name", "")):
                
                status_phase = pod.status.phase.lower() if pod.status.phase else "unknown"
                container_id = pod.metadata.uid  # Kubernetes pod UID
                
                # Get ready status from container status
                ready = False
                restart_count = 0
                message = ""
                
                if pod.status.container_statuses:
                    # Check if all containers are ready
                    ready = all(cs.ready for cs in pod.status.container_statuses)
                    # Get restart count from first container
                    if pod.status.container_statuses[0]:
                        restart_count = pod.status.container_statuses[0].restart_count
                        # Get state message
                        state = pod.status.container_statuses[0].state
                        if state.waiting:
                            message = state.waiting.reason or "Waiting"
                        elif state.terminated:
                            message = state.terminated.reason or "Terminated"
                        elif state.running:
                            message = "Running"
                
                return {
                    "status": status_phase,
                    "container_id": container_id,
                    "ready": ready,
                    "restart_count": restart_count,
                    "message": message,
                    "pod_name": pod.metadata.name
                }
        
        return {
            "status": "not_found",
            "container_id": None,
            "ready": False,
            "restart_count": 0,
            "message": "Pod not found",
            "pod_name": None
        }
    except Exception as e:
        logger.error(f"Error getting pod status: {e}")
        return {
            "status": "error",
            "container_id": None,
            "ready": False,
            "restart_count": 0,
            "message": str(e),
            "pod_name": None
        }


async def get_pod_status(pod_name: str) -> str:
    """Get pod status from Kubernetes (simplified, for backward compatibility)"""
    info = await get_pod_status_and_info(pod_name)
    return info.get("status", "unknown")


# MCP Server endpoints
@app.get("/api/mcp-servers", response_model=List[MCPServerResponse])
async def list_mcp_servers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all MCP servers"""
    servers = db.query(MCPServer).all()
    return servers


@app.post("/api/mcp-servers", response_model=MCPServerResponse)
async def create_mcp_server(
    server: MCPServerCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new MCP server (converts swagger and spawns pod)"""
    import httpx
    import re
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    mcp_sync_url = os.getenv("MCP_LITELLM_SYNC_URL", "http://mcp-litellm-sync:4008")
    
    # Generate subdomain from name
    subdomain = re.sub(r'[^a-z0-9-]', '', server.name.lower().replace(' ', '-'))
    
    # Get department (required for MCP pods)
    # For now, use a default department or require it in the request
    # TODO: Add department selection to UI
    depts_response = await httpx.AsyncClient().get(f"{pod_spawner_url}/api/v1/departments")
    if depts_response.status_code == 200:
        departments = depts_response.json()
        if departments:
            department_id = departments[0]["id"]  # Use first department for now
        else:
            # Create default department
            dept_create = await httpx.AsyncClient().post(
                f"{pod_spawner_url}/api/v1/departments",
                json={"name": "Default"}
            )
            department_id = dept_create.json()["id"]
    else:
        raise HTTPException(status_code=500, detail="Failed to get departments")
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            # Spawn MCP pod via pod-spawner
            spawn_response = await client.post(
                f"{pod_spawner_url}/api/v1/pods/spawn",
                json={
                    "pod_type": "mcp",
                    "department_id": department_id,
                    "name": server.name,
                    "subdomain": subdomain,
                    "swagger_file": server.swagger_file
                }
            )
            spawn_response.raise_for_status()
            result = spawn_response.json()
            
            # Check if pod creation was successful
            if not result.get("success", False):
                raise HTTPException(status_code=500, detail=f"Pod creation failed: {result.get('message', 'Unknown error')}")
            
            # Register MCP server with LiteLLM
            mcp_url = result.get("url", "")
            mcp_service_name = result.get("service_name", f"mcp-{subdomain}")
            # Use internal cluster URL for LiteLLM access
            internal_url = f"http://{mcp_service_name}:8000"
            
            try:
                register_response = await client.post(
                    f"{mcp_sync_url}/register",
                    json={
                        "name": subdomain,  # Use subdomain as MCP server name
                        "url": mcp_url,  # External URL
                        "internal_url": internal_url  # Internal cluster URL
                    },
                    timeout=30.0
                )
                register_response.raise_for_status()
                logger.info(f"Registered MCP server '{subdomain}' with LiteLLM")
            except Exception as reg_error:
                logger.warning(f"Failed to register MCP server with LiteLLM (non-fatal): {reg_error}")
                # Continue even if registration fails - pod is still created
            
            # Store in admin portal DB - set status based on result
            db_server = MCPServer(
                name=server.name,
                swagger_file=server.swagger_file,
                url=mcp_url,
                status="running" if result.get("success") else "error",
                pod_name=result.get("container_name", ""),
                service_name=result.get("container_name", "")
            )
            db.add(db_server)
            db.commit()
            db.refresh(db_server)
            
            return db_server
    except httpx.HTTPStatusError as e:
        logger.error(f"Error creating MCP server: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error creating MCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/mcp-servers/{server_id}")
async def delete_mcp_server(
    server_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an MCP server"""
    import httpx
    server = db.query(MCPServer).filter(MCPServer.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found")
    
    # Delete pod via pod-spawner if pod_name exists
    if server.pod_name:
        pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get pod ID from pod-spawner
                pods_response = await client.get(f"{pod_spawner_url}/api/v1/pods")
                if pods_response.status_code == 200:
                    pods = pods_response.json()
                    for pod in pods:
                        if pod.get("container_name") == server.pod_name:
                            delete_response = await client.delete(
                                f"{pod_spawner_url}/api/v1/pods/{pod['id']}"
                            )
                            break
        except Exception as e:
            logger.warning(f"Failed to delete pod via pod-spawner: {e}")
    
    db.delete(server)
    db.commit()
    return {"message": "MCP server deleted successfully"}


# Voice Agent endpoints
@app.get("/api/voice-agents", response_model=List[VoiceAgentResponse])
async def list_voice_agents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all voice agents"""
    agents = db.query(VoiceAgent).all()
    return agents


@app.post("/api/voice-agents", response_model=VoiceAgentResponse)
async def create_voice_agent(
    agent: VoiceAgentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new voice agent scenario"""
    db_agent = VoiceAgent(
        scenario_name=agent.scenario_name,
        description=agent.description,
        mcp_endpoints=agent.mcp_endpoints,
        n8n_instance_id=agent.n8n_instance_id,
        auth_needed=agent.auth_needed,
        auth_config=agent.auth_config
    )
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return db_agent


@app.delete("/api/voice-agents/{agent_id}")
async def delete_voice_agent(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a voice agent"""
    agent = db.query(VoiceAgent).filter(VoiceAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Voice agent not found")
    
    db.delete(agent)
    db.commit()
    return {"message": "Voice agent deleted successfully"}


# Development Agent endpoints
@app.get("/api/dev-agents", response_model=List[DevAgentResponse])
async def list_dev_agents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all development agents"""
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    # Get dev-agent pods from pod-spawner
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            pods_response = await client.get(f"{pod_spawner_url}/api/v1/pods")
            if pods_response.status_code == 200:
                all_pods = pods_response.json()
                dev_agent_pods = [p for p in all_pods if p.get("pod_type") == "dev-agent"]
                
                # Convert to dev agent response format
                agents = []
                for pod in dev_agent_pods:
                    status = await get_pod_status(pod.get("container_name", ""))
                    type_config = pod.get("type_config", {})
                    agents.append({
                        "id": pod["id"],
                        "name": pod["name"],
                        "description": type_config.get("requirements", ""),
                        "repo_urls": type_config.get("repo_urls", []),
                        "url": pod.get("url", f"http://{pod['subdomain']}.dev-agent.{os.getenv('DEV_AGENT_BASE_DOMAIN', 'localhost')}"),
                        "status": status,
                        "created_at": pod.get("created_at", "")
                    })
                return agents
    except Exception as e:
        logger.error(f"Error fetching dev agents: {e}")
        # Fallback to DB
        return db.query(DevelopmentAgent).all()


@app.post("/api/dev-agents", response_model=DevAgentResponse)
async def create_dev_agent(
    agent: DevAgentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new development agent (spawns pod)"""
    import httpx
    import re
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    # Generate subdomain from name
    subdomain = re.sub(r'[^a-z0-9-]', '', agent.name.lower().replace(' ', '-'))
    
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            # Spawn dev-agent pod via pod-spawner (no department_id needed - auto-assigned)
            spawn_response = await client.post(
                f"{pod_spawner_url}/api/v1/pods/spawn",
                json={
                    "pod_type": "dev-agent",
                    "name": agent.name,
                    "subdomain": subdomain,
                    "repo_urls": agent.repo_urls,
                    "cursor_api_key": agent.cursor_api_key,
                    "requirements": agent.description or "",
                    "git_config": {}
                }
            )
            spawn_response.raise_for_status()
            result = spawn_response.json()
            
            # Store in admin portal DB
            db_agent = DevelopmentAgent(
                name=agent.name,
                description=agent.description,
                repo_urls=agent.repo_urls,
                cursor_api_key=agent.cursor_api_key,
                url=result.get("url", ""),
                status="running",
                pod_name=result.get("container_name", ""),
                service_name=result.get("container_name", "")
            )
            db.add(db_agent)
            db.commit()
            db.refresh(db_agent)
            
            return db_agent
    except httpx.HTTPStatusError as e:
        logger.error(f"Error creating dev agent: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        logger.error(f"Error creating dev agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/dev-agents/{agent_id}")
async def delete_dev_agent(
    agent_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a development agent"""
    import httpx
    agent = db.query(DevelopmentAgent).filter(DevelopmentAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Dev agent not found")
    
    # Delete pod via pod-spawner if pod_name exists
    if agent.pod_name:
        pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get pod ID from pod-spawner
                pods_response = await client.get(f"{pod_spawner_url}/api/v1/pods")
                if pods_response.status_code == 200:
                    pods = pods_response.json()
                    for pod in pods:
                        if pod.get("container_name") == agent.pod_name:
                            delete_response = await client.delete(
                                f"{pod_spawner_url}/api/v1/pods/{pod['id']}"
                            )
                            break
        except Exception as e:
            logger.warning(f"Failed to delete pod via pod-spawner: {e}")
    
    db.delete(agent)
    db.commit()
    return {"message": "Dev agent deleted successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4006, log_level="info")

