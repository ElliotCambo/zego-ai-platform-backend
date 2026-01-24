"""
Database connection and session management for Admin Portal
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Database URL from environment - using the same PostgreSQL instance
DATABASE_URL = (
    f"postgresql://{os.getenv('ADMIN_DB_USER', 'litellm')}:"
    f"{os.getenv('ADMIN_DB_PASSWORD', 'litellm')}@"
    f"{os.getenv('ADMIN_DB_HOST', 'zego-postgres')}:"
    f"{os.getenv('ADMIN_DB_PORT', '5432')}/"
    f"{os.getenv('ADMIN_DB_NAME', 'litellm')}"
)

engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    echo=False  # Set to True for SQL query logging
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for FastAPI to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    from models import User, MCPServer, VoiceAgent, DevelopmentAgent, N8nPodApiKey
    Base.metadata.create_all(bind=engine)
    
    # Create default admin user if it doesn't exist
    import bcrypt
    from models import User
    
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            # Hash password using bcrypt directly (matching app.py)
            password_hash = bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            admin_user = User(
                username="admin",
                email="admin@zego.ai",
                password_hash=password_hash,
                is_active=True,
                is_admin=True
            )
            db.add(admin_user)
            db.commit()
            print("Default admin user created: admin/admin")
        else:
            # Re-hash password if it was created with passlib (for existing users)
            try:
                import bcrypt
                test_verify = bcrypt.checkpw("admin".encode('utf-8'), admin_user.password_hash.encode('utf-8'))
                if not test_verify:
                    # Password hash is incompatible, re-hash it
                    admin_user.password_hash = bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    db.commit()
                    print("Admin user password re-hashed for compatibility")
            except:
                # If verification fails, re-hash
                admin_user.password_hash = bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                db.commit()
                print("Admin user password re-hashed for compatibility")
    except Exception as e:
        print(f"Error creating default admin user: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()

