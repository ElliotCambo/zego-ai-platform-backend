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
from models import User, MCPServer, VoiceAgent, DevelopmentAgent, N8nPodApiKey
from schemas import (
    UserCreate, UserResponse, UserLogin,
    N8nPodResponse, N8nPodCreate, N8nPodApiKeyUpdate, WorkflowResponse,
    MCPServerCreate, MCPServerResponse, MCPServerUpdate,
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
        # Increase default expiration to 24 hours for better UX
        expire = datetime.utcnow() + timedelta(hours=24)
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
                        # Only include n8n pods
                        if pod.get("pod_type") != "n8n":
                            continue
                        # Get detailed pod status from Kubernetes first
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
                        service_name = pod.get("container_name", f"n8n-{pod['subdomain']}")
                        try:
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
                            # If service type is LoadBalancer but no hostname yet, wait a bit
                            elif service.spec.type == "LoadBalancer":
                                # Service is LoadBalancer but hostname not ready yet
                                # This is OK - it will be available on next refresh
                                logger.debug(f"LoadBalancer service {service_name} exists but hostname not ready yet")
                        except Exception as e:
                            logger.debug(f"Could not get service info for {service_name}: {e}")
                        
                        # Fallback: Construct URL from domain/env if no LoadBalancer (local dev only)
                        if not url:
                            aws_region = os.getenv("AWS_REGION")
                            if not aws_region:
                                # Only use localhost fallback if not in AWS
                                n8n_base_domain = os.getenv("N8N_BASE_DOMAIN", "localhost")
                                traefik_port = os.getenv("TRAEFIK_NODEPORT", "30080")
                                url = f"http://{pod['subdomain']}.n8n.{n8n_base_domain}:{traefik_port}"
                            else:
                                # In AWS but LoadBalancer not ready - return placeholder
                                url = f"http://{service_name}.pending"
                        
                        # Check URL accessibility if we have a valid URL (not pending/loading)
                        url_accessible = False
                        if url and not url.endswith(".pending") and "Loading" not in url:
                            try:
                                url_accessible = await check_url_accessible(url, timeout=3.0)
                            except Exception as e:
                                logger.debug(f"Could not check URL accessibility for {url}: {e}")
                        
                        # Get API key from admin portal DB
                        api_key_record = db.query(N8nPodApiKey).filter(N8nPodApiKey.pod_id == pod["id"]).first()
                        api_key = api_key_record.api_key if api_key_record else None
                        
                        # Determine status - only show "running" if pod is ready AND URL is accessible
                        status = pod_info.get("status", "unknown")
                        aws_region = os.getenv("AWS_REGION")
                        if aws_region and (not url or "pending" in url):
                            # In AWS and LoadBalancer not ready - show as pending
                            status = "pending"
                        elif status == "running" and not pod_info.get("ready", False):
                            # Pod is running but not ready yet
                            status = "pending"
                        elif status == "running" and url and not url.endswith(".pending") and "Loading" not in url:
                            # Pod is running but URL not accessible - show as pending until URL is accessible
                            if not url_accessible:
                                status = "pending"
                        
                        pods_list.append({
                            "id": pod["id"],
                            "name": pod["name"],
                            "department_name": dept["name"],
                            "subdomain": pod["subdomain"],
                            "url": url if not url.endswith(".pending") else "Loading...",
                            "status": status,
                            "container_id": pod_info.get("container_id"),
                            "created_at": pod["created_at"],
                            "enabled_nodes": pod.get("nodes_exclude", ""),
                            "api_key": api_key
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
        # Increased timeout to 120 seconds to allow for LoadBalancer provisioning
        async with httpx.AsyncClient(timeout=120.0) as client:
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
            
            # Wait for LoadBalancer URL if in AWS
            pod_id = result.get("pod_id")
            container_name = result.get("container_name", "")
            aws_region = os.getenv("AWS_REGION")
            
            if aws_region and pod_id:
                # Poll for LoadBalancer hostname (with shorter timeout to avoid blocking)
                import asyncio
                max_attempts = 10  # Reduced from 30 - don't wait too long, URL will be fetched on list
                for attempt in range(max_attempts):
                    try:
                        # Query Kubernetes service for LoadBalancer hostname
                        from kubernetes import client as k8s_client, config as k8s_config
                        try:
                            k8s_config.load_incluster_config()
                        except:
                            k8s_config.load_kube_config()
                        v1 = k8s_client.CoreV1Api()
                        namespace = os.getenv("KUBERNETES_NAMESPACE", "zego-ai-platform")
                        service = v1.read_namespaced_service(
                            name=container_name,
                            namespace=namespace
                        )
                        if (service.status.load_balancer and 
                            service.status.load_balancer.ingress and 
                            len(service.status.load_balancer.ingress) > 0):
                            lb_hostname = service.status.load_balancer.ingress[0].hostname
                            if lb_hostname:
                                result["url"] = f"http://{lb_hostname}"
                                break
                    except Exception as e:
                        logger.debug(f"Waiting for LoadBalancer (attempt {attempt + 1}/{max_attempts}): {e}")
                    await asyncio.sleep(2)
            
            # If still no LoadBalancer URL, use the URL from pod-spawner (or construct fallback)
            if not result.get("url") or "localhost" in result.get("url", ""):
                # Try to get from list endpoint which has better URL logic
                pods_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{pod_id}")
                if pods_response.status_code == 200:
                    pod_data = pods_response.json()
                    # Get URL using same logic as list endpoint
                    service_name = pod_data.get("container_name", container_name)
                    try:
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
                        if (service.status.load_balancer and 
                            service.status.load_balancer.ingress and 
                            len(service.status.load_balancer.ingress) > 0):
                            lb_hostname = service.status.load_balancer.ingress[0].hostname
                            if lb_hostname:
                                result["url"] = f"http://{lb_hostname}"
                    except Exception:
                        pass
            
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


@app.patch("/api/n8n-pods/{pod_id}/api-key")
async def update_n8n_pod_api_key(
    pod_id: int,
    api_key_update: N8nPodApiKeyUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update API key for an n8n pod"""
    # Get pod name from pod-spawner for reference
    import httpx
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            pod_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{pod_id}")
            if pod_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Pod not found")
            pod_data = pod_response.json()
            pod_name = pod_data.get("name", "")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    
    # Update or create API key record
    api_key_record = db.query(N8nPodApiKey).filter(N8nPodApiKey.pod_id == pod_id).first()
    if api_key_record:
        api_key_record.api_key = api_key_update.api_key
        api_key_record.pod_name = pod_name
    else:
        api_key_record = N8nPodApiKey(
            pod_id=pod_id,
            pod_name=pod_name,
            api_key=api_key_update.api_key
        )
        db.add(api_key_record)
    
    db.commit()
    return {"message": "API key updated successfully", "pod_id": pod_id}


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
                # Also delete API key record
                api_key_record = db.query(N8nPodApiKey).filter(N8nPodApiKey.pod_id == pod_id).first()
                if api_key_record:
                    db.delete(api_key_record)
                    db.commit()
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


@app.get("/api/n8n-pods/{pod_id}/users")
async def get_n8n_pod_users(
    pod_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of users from a specific n8n pod"""
    import httpx
    
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get pod details
            pod_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{pod_id}")
            if pod_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Pod not found")
            
            pod_data = pod_response.json()
            subdomain = pod_data.get("subdomain")
            container_name = pod_data.get("container_name", f"n8n-{subdomain}")
            
            # Get API key from admin portal DB
            api_key_record = db.query(N8nPodApiKey).filter(N8nPodApiKey.pod_id == pod_id).first()
            if not api_key_record or not api_key_record.api_key:
                raise HTTPException(status_code=400, detail="API key not set for this pod. Please set it first.")
            
            # Get users from n8n API
            n8n_api_url = f"http://{container_name}:80"
            users_response = await client.get(
                f"{n8n_api_url}/api/v1/users",
                headers={"X-N8N-API-KEY": api_key_record.api_key},
                timeout=10.0
            )
            
            if users_response.status_code != 200:
                raise HTTPException(
                    status_code=users_response.status_code,
                    detail=f"Failed to fetch users from n8n: {users_response.text}"
                )
            
            users_data = users_response.json()
            users = users_data.get("data", [])
            
            # Format users for frontend
            formatted_users = [
                {
                    "id": user.get("id"),
                    "email": user.get("email"),
                    "firstName": user.get("firstName", ""),
                    "lastName": user.get("lastName", ""),
                    "isOwner": user.get("isOwner", False)
                }
                for user in users
            ]
            
            return {"users": formatted_users}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching n8n pod users: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch users: {str(e)}")


@app.post("/api/workflow-generation")
async def generate_workflow(
    request: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate a workflow from description and push it to a specific n8n pod"""
    import httpx
    
    pod_id = request.get("pod_id")
    description = request.get("description")
    workflow_name = request.get("workflow_name")
    
    if not pod_id or not description:
        raise HTTPException(status_code=400, detail="pod_id and description are required")
    
    # Get pod info from pod-spawner
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    workflow_api_url = os.getenv("WORKFLOW_API_URL", "http://zego-workflow-api:4009")
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # Get pod details
            pod_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{pod_id}")
            if pod_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Pod not found")
            
            pod_data = pod_response.json()
            subdomain = pod_data.get("subdomain")
            
            if not subdomain:
                raise HTTPException(status_code=400, detail="Pod subdomain not found")
            
            # Get pod URL (LoadBalancer URL in AWS)
            pod_url = None
            try:
                from kubernetes import client as k8s_client, config as k8s_config
                try:
                    k8s_config.load_incluster_config()
                except:
                    k8s_config.load_kube_config()
                v1 = k8s_client.CoreV1Api()
                namespace = os.getenv("KUBERNETES_NAMESPACE", "zego-ai-platform")
                container_name = pod_data.get("container_name", f"n8n-{subdomain}")
                service = v1.read_namespaced_service(
                    name=container_name,
                    namespace=namespace
                )
                if (service.status.load_balancer and 
                    service.status.load_balancer.ingress and 
                    len(service.status.load_balancer.ingress) > 0):
                    lb_hostname = service.status.load_balancer.ingress[0].hostname
                    pod_url = f"http://{lb_hostname}"
            except Exception as e:
                logger.warning(f"Could not get LoadBalancer URL: {e}")
                # Fallback to constructing URL
                pod_url = f"http://{subdomain}.n8n.localhost"
            
            # Get API key from admin portal DB
            api_key_record = db.query(N8nPodApiKey).filter(N8nPodApiKey.pod_id == pod_id).first()
            if not api_key_record or not api_key_record.api_key:
                raise HTTPException(status_code=400, detail="API key not set for this pod. Please set it first.")
            
            # Get user emails from request (default to current user if not provided)
            user_emails = request.get("user_emails", [current_user.email])
            if not isinstance(user_emails, list):
                user_emails = [user_emails]
            
            # Call workflow-api to generate workflow
            workflow_request = {
                "description": description,
                "user_emails": user_emails,
                "workflow_name": workflow_name,
                "subdomain": subdomain,
                "api_key": api_key_record.api_key  # Pass API key from admin portal DB
            }
            
            # Debug logging
            logger.info(f"DEBUG: Sending workflow request - subdomain: {subdomain}, api_key length: {len(api_key_record.api_key) if api_key_record.api_key else 0}, pod_id: {pod_id}")
            logger.info(f"DEBUG: Workflow request keys: {list(workflow_request.keys())}")
            
            workflow_response = await client.post(
                f"{workflow_api_url}/api/v1/workflows/create",
                json=workflow_request,
                timeout=120.0  # Workflow generation can take time
            )
            
            if workflow_response.status_code != 201:
                error_detail = workflow_response.text
                raise HTTPException(
                    status_code=workflow_response.status_code,
                    detail=f"Workflow generation failed: {error_detail}"
                )
            
            workflow_data = workflow_response.json()
            
            # Construct the public workflow URL
            workflow_id = workflow_data.get("workflow_id")
            public_workflow_url = f"{pod_url}/workflow/{workflow_id}"
            
            # Construct curl command
            is_webhook = "/webhook/" in workflow_data.get("workflow_url", "")
            method = "POST" if is_webhook else "GET"
            curl_command = f'curl -X {method} "{public_workflow_url}" -H "X-N8N-API-KEY: {api_key_record.api_key}"'
            
            return {
                "success": True,
                "workflow_id": workflow_id,
                "workflow_url": public_workflow_url,
                "workflow_name": workflow_data.get("summary", "").split(":")[0] if workflow_data.get("summary") else workflow_name or "Unnamed",
                "summary": workflow_data.get("summary", ""),
                "nodes_used": workflow_data.get("nodes_used", []),
                "curl_command": curl_command
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating workflow: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate workflow: {str(e)}")


@app.get("/api/n8n-workflows", response_model=List[WorkflowResponse])
async def list_n8n_workflows(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all workflows from all n8n instances that have API keys"""
    import httpx
    from datetime import datetime
    
    # Get all pods with API keys
    api_key_records = db.query(N8nPodApiKey).filter(N8nPodApiKey.api_key.isnot(None)).all()
    
    # Get pod details from pod-spawner
    pod_spawner_url = os.getenv("POD_SPAWNER_URL", "http://zego-pod-spawner:4005")
    workflows_list = []
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            for api_key_record in api_key_records:
                try:
                    # Get pod info
                    pod_response = await client.get(f"{pod_spawner_url}/api/v1/pods/{api_key_record.pod_id}")
                    if pod_response.status_code != 200:
                        continue
                    pod_data = pod_response.json()
                    
                    # Get pod URL
                    container_name = pod_data.get("container_name", "")
                    pod_url = None
                    
                    # Try to get LoadBalancer URL
                    try:
                        from kubernetes import client as k8s_client, config as k8s_config
                        try:
                            k8s_config.load_incluster_config()
                        except:
                            k8s_config.load_kube_config()
                        v1 = k8s_client.CoreV1Api()
                        namespace = os.getenv("KUBERNETES_NAMESPACE", "zego-ai-platform")
                        service = v1.read_namespaced_service(
                            name=container_name,
                            namespace=namespace
                        )
                        if (service.status.load_balancer and 
                            service.status.load_balancer.ingress and 
                            len(service.status.load_balancer.ingress) > 0):
                            lb_hostname = service.status.load_balancer.ingress[0].hostname
                            if lb_hostname:
                                pod_url = f"http://{lb_hostname}"
                    except Exception:
                        pass
                    
                    if not pod_url:
                        n8n_base_domain = os.getenv("N8N_BASE_DOMAIN", "localhost")
                        traefik_port = os.getenv("TRAEFIK_NODEPORT", "30080")
                        pod_url = f"http://{pod_data.get('subdomain', '')}.n8n.{n8n_base_domain}:{traefik_port}"
                    
                    # Get container ID
                    pod_info = await get_pod_status_and_info(container_name)
                    container_id = pod_info.get("container_id")
                    
                    # Fetch workflows from n8n API
                    n8n_api_url = f"{pod_url}/api/v1/workflows"
                    headers = {"X-N8N-API-KEY": api_key_record.api_key}
                    workflows_response = await client.get(n8n_api_url, headers=headers, timeout=10.0)
                    
                    if workflows_response.status_code == 200:
                        workflows_data = workflows_response.json()
                        if isinstance(workflows_data, dict) and "data" in workflows_data:
                            workflows = workflows_data["data"]
                        elif isinstance(workflows_data, list):
                            workflows = workflows_data
                        else:
                            workflows = []
                        
                        for workflow in workflows:
                            # Get webhook URL if available
                            workflow_url = None
                            if "nodes" in workflow:
                                for node in workflow.get("nodes", []):
                                    if node.get("type") == "n8n-nodes-base.webhook":
                                        webhook_path = node.get("parameters", {}).get("path", "")
                                        if webhook_path:
                                            workflow_url = f"{pod_url}/webhook/{webhook_path}"
                                            break
                            
                            # Parse dates
                            created_at = None
                            updated_at = None
                            if workflow.get("createdAt"):
                                try:
                                    created_at = datetime.fromisoformat(workflow["createdAt"].replace("Z", "+00:00"))
                                except:
                                    pass
                            if workflow.get("updatedAt"):
                                try:
                                    updated_at = datetime.fromisoformat(workflow["updatedAt"].replace("Z", "+00:00"))
                                except:
                                    pass
                            
                            workflows_list.append({
                                "id": str(workflow.get("id", "")),
                                "name": workflow.get("name", "Unnamed Workflow"),
                                "url": workflow_url or f"{pod_url}/workflow/{workflow.get('id', '')}",
                                "container_id": container_id,
                                "created_at": created_at,
                                "updated_at": updated_at,
                                "owner": workflow.get("nodes", [{}])[0].get("parameters", {}).get("owner", None) if workflow.get("nodes") else None,
                                "active": workflow.get("active", False),
                                "pod_name": api_key_record.pod_name,
                                "pod_id": api_key_record.pod_id
                            })
                except Exception as e:
                    logger.error(f"Error fetching workflows for pod {api_key_record.pod_id}: {e}")
                    continue
        
        return workflows_list
    except Exception as e:
        logger.error(f"Error fetching n8n workflows: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def check_url_accessible(url: str, timeout: float = 5.0) -> bool:
    """Check if a URL is accessible via HTTP GET"""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            # Consider 2xx, 3xx, and 401/403 (login pages) as accessible
            return response.status_code < 500
    except Exception:
        return False


async def get_pod_status_and_info(pod_name: str) -> dict:
    """Get pod status and detailed info from Kubernetes
    
    Returns:
        dict with keys: status, container_id, ready, restart_count, message, url_accessible
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
                url_accessible = False
                
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
                    "pod_name": pod.metadata.name,
                    "url_accessible": url_accessible  # Will be set by caller with URL check
                }
        
        return {
            "status": "not_found",
            "container_id": None,
            "ready": False,
            "restart_count": 0,
            "message": "Pod not found",
            "pod_name": None,
            "url_accessible": False
        }
    except Exception as e:
        logger.error(f"Error getting pod status: {e}")
        return {
            "status": "error",
            "container_id": None,
            "ready": False,
            "restart_count": 0,
            "message": str(e),
            "pod_name": None,
            "url_accessible": False
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
    """List all MCP servers with updated status from Kubernetes"""
    servers = db.query(MCPServer).all()
    
    # Update status based on actual pod status
    for server in servers:
        if server.pod_name:
            try:
                pod_info = await get_pod_status_and_info(server.pod_name)
                pod_status = pod_info.get("status", "unknown")
                
                # Map Kubernetes status to our status
                if pod_status == "running" and pod_info.get("ready", False):
                    new_status = "running"
                elif pod_status in ["pending", "containercreating"]:
                    new_status = "pending"
                elif pod_status in ["error", "crashloopbackoff", "imagepullbackoff"]:
                    new_status = "error"
                else:
                    new_status = pod_status
                
                # Update database if status changed
                if server.status != new_status:
                    server.status = new_status
                    db.commit()
                    db.refresh(server)
            except Exception as e:
                logger.error(f"Error checking pod status for {server.pod_name}: {e}")
                # Keep existing status if check fails
    
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
                    "swagger_file": server.swagger_file,
                    "api_url": server.api_url  # Pass API URL where swagger API is hosted
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
                # Register with mcp-litellm-sync
                # Note: subdomain may contain hyphens, but LiteLLM database requires underscores
                # mcp-litellm-sync will handle the conversion
                register_response = await client.post(
                    f"{mcp_sync_url}/register",
                    json={
                        "name": subdomain,  # Use subdomain as MCP server name (may contain hyphens)
                        "url": mcp_url,  # External URL
                        "internal_url": internal_url,  # Internal cluster URL
                        "api_key": os.getenv("LITELLM_MASTER_KEY", "sk-1234"),  # Use master key for auth
                        "db_name": subdomain.replace("-", "_")  # Database-friendly name (underscores)
                    },
                    timeout=30.0
                )
                register_response.raise_for_status()
                register_result = register_response.json()
                logger.info(f"Registered MCP server '{subdomain}' with LiteLLM: {register_result}")
                
                # Extract LiteLLM server_id from registration response if available
                litellm_server_id = None
                if isinstance(register_result, dict):
                    # Try different possible response formats
                    litellm_server_id = register_result.get("server_id") or register_result.get("id") or register_result.get("data", {}).get("server_id")
            except Exception as reg_error:
                logger.error(f"Failed to register MCP server with LiteLLM: {reg_error}", exc_info=True)
                # Continue even if registration fails - pod is still created
                # Note: Registration can be retried or done manually via LiteLLM UI
                litellm_server_id = None
            
            # Store in admin portal DB - set status based on actual pod status
            # Wait a bit for pod to start, then check status with retries
            import asyncio
            pod_status = "pending"
            if result.get("success"):
                pod_name = result.get("container_name", "")
                if pod_name:
                    # Wait 5 seconds for pod to start initializing
                    await asyncio.sleep(5)
                    
                    # Check pod status with retries (pods take time to become ready)
                    max_retries = 6  # Check for up to 30 seconds (6 * 5s)
                    for attempt in range(max_retries):
                        try:
                            pod_info = await get_pod_status_and_info(pod_name)
                            k8s_status = pod_info.get("status", "unknown")
                            ready = pod_info.get("ready", False)
                            
                            # Map Kubernetes status to our status
                            if k8s_status == "running" and ready:
                                # Verify health by checking MCP server health endpoint
                                try:
                                    health_url = f"{internal_url}/health"
                                    async with httpx.AsyncClient(timeout=5.0) as health_client:
                                        health_response = await health_client.get(health_url)
                                        if health_response.status_code == 200:
                                            pod_status = "running"
                                            break
                                        else:
                                            logger.warning(f"MCP server health check failed: {health_response.status_code}")
                                except Exception as health_error:
                                    logger.warning(f"Could not verify MCP server health: {health_error}")
                                    # Still mark as running if pod is ready (health check might be timing out)
                                    if attempt >= 3:  # After 15 seconds, accept pod as running even if health check fails
                                        pod_status = "running"
                                        break
                            elif k8s_status in ["error", "crashloopbackoff", "imagepullbackoff"]:
                                pod_status = "error"
                                break
                            elif k8s_status in ["pending", "containercreating"]:
                                # Still starting, wait and retry
                                if attempt < max_retries - 1:
                                    await asyncio.sleep(5)
                                    continue
                                else:
                                    pod_status = "pending"
                                    break
                            else:
                                pod_status = k8s_status
                                break
                        except Exception as status_error:
                            logger.warning(f"Could not check pod status (attempt {attempt + 1}): {status_error}")
                            if attempt < max_retries - 1:
                                await asyncio.sleep(5)
                            else:
                                pod_status = "pending"
                                break
                else:
                    pod_status = "pending"
            else:
                pod_status = "error"
            
            db_server = MCPServer(
                name=server.name,
                swagger_file=server.swagger_file,
                api_url=server.api_url,  # Store the API URL where swagger API is hosted
                url=mcp_url,
                status=pod_status,
                pod_name=result.get("container_name", ""),
                service_name=result.get("service_name", result.get("container_name", "")),
                litellm_server_id=litellm_server_id  # Store LiteLLM's server_id
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


@app.get("/api/mcp-servers/{server_id}")
async def get_mcp_server(
    server_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a single MCP server with full details including swagger_file"""
    server = db.query(MCPServer).filter(MCPServer.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found")
    
    return {
        "id": server.id,
        "name": server.name,
        "url": server.url,
        "api_url": server.api_url,
        "swagger_file": server.swagger_file,
        "status": server.status,
        "created_at": server.created_at
    }


@app.patch("/api/mcp-servers/{server_id}", response_model=MCPServerResponse)
async def update_mcp_server(
    server_id: int,
    server_update: MCPServerUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an MCP server's API URL and/or swagger file"""
    server = db.query(MCPServer).filter(MCPServer.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found")
    
    # Update fields if provided
    if server_update.api_url is not None:
        server.api_url = server_update.api_url
    
    if server_update.swagger_file is not None:
        server.swagger_file = server_update.swagger_file
        # TODO: If swagger is updated, we might want to re-convert and update the MCP config
        # For now, just update the stored swagger file
    
    server.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(server)
    
    return server


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
    
    # Unregister from LiteLLM first
    mcp_sync_url = os.getenv("MCP_LITELLM_SYNC_URL", "http://mcp-litellm-sync:4008")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Use server_id if available (more reliable), otherwise fall back to name
            unregister_url = f"{mcp_sync_url}/unregister/{server.name}"
            if server.litellm_server_id:
                unregister_url += f"?server_id={server.litellm_server_id}"
            unregister_response = await client.delete(unregister_url)
            if unregister_response.status_code == 200:
                logger.info(f"Unregistered MCP server '{server.name}' from LiteLLM")
            else:
                logger.warning(f"Failed to unregister MCP server from LiteLLM: {unregister_response.text}")
    except Exception as unreg_error:
        logger.error(f"Error unregistering MCP server from LiteLLM: {unreg_error}")
        # Continue with deletion even if unregistration fails
    
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

