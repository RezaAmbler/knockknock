"""Pytest configuration and fixtures"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from web.main import create_app
from web.database import Base, get_db
from web.config import settings

# Test database
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create test database"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Create test client"""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="function")
def admin_token(client, db):
    """Create admin user and return auth token"""
    from web.models.user import User, UserRole
    from web.auth.security import get_password_hash

    user = User(
        email="admin@test.com",
        password_hash=get_password_hash("password"),
        role=UserRole.ADMIN
    )
    db.add(user)
    db.commit()

    response = client.post("/api/auth/login", json={
        "email": "admin@test.com",
        "password": "password"
    })

    return response.json()["access_token"]


@pytest.fixture(scope="function")
def user_token(client, db):
    """Create regular user and return auth token"""
    from web.models.user import User, UserRole
    from web.auth.security import get_password_hash

    user = User(
        email="user@test.com",
        password_hash=get_password_hash("password"),
        role=UserRole.USER
    )
    db.add(user)
    db.commit()

    response = client.post("/api/auth/login", json={
        "email": "user@test.com",
        "password": "password"
    })

    return response.json()["access_token"]
