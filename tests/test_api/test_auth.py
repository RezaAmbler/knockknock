"""Test authentication endpoints"""

import pytest


def test_register_user(client):
    """Test user registration"""
    response = client.post("/api/auth/register", json={
        "email": "newuser@example.com",
        "password": "password123",
        "timezone": "America/New_York"
    })

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["role"] == "user"


def test_login_success(admin_token):
    """Test successful login"""
    assert admin_token is not None


def test_login_failure(client):
    """Test login with wrong password"""
    response = client.post("/api/auth/login", json={
        "email": "admin@test.com",
        "password": "wrongpassword"
    })

    assert response.status_code == 401


def test_get_current_user(client, admin_token):
    """Test getting current user info"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/auth/me", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "admin@test.com"
    assert data["role"] == "admin"
