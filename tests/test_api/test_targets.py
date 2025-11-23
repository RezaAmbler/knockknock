"""Test targets API"""

import pytest


def test_create_target(client, admin_token):
    """Test creating a target"""
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = client.post(
        "/api/targets",
        json={
            "friendly_name": "Test Firewall",
            "ip_address": "192.168.1.1",
            "description": "Test device"
        },
        headers=headers
    )

    assert response.status_code == 201
    data = response.json()
    assert data["friendly_name"] == "Test Firewall"
    assert data["ip_address"] == "192.168.1.1"


def test_list_targets(client, admin_token):
    """Test listing targets"""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create some targets first
    for i in range(3):
        client.post(
            "/api/targets",
            json={
                "friendly_name": f"Target {i}",
                "ip_address": f"192.168.1.{i+1}"
            },
            headers=headers
        )

    # List targets
    response = client.get("/api/targets", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["targets"]) == 3


def test_get_target(client, admin_token):
    """Test getting a single target"""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create target
    create_response = client.post(
        "/api/targets",
        json={
            "friendly_name": "Test Target",
            "ip_address": "10.0.0.1"
        },
        headers=headers
    )

    target_id = create_response.json()["id"]

    # Get target
    response = client.get(f"/api/targets/{target_id}", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == target_id
    assert data["friendly_name"] == "Test Target"


def test_delete_target(client, admin_token):
    """Test deleting a target"""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create target
    create_response = client.post(
        "/api/targets",
        json={
            "friendly_name": "Delete Me",
            "ip_address": "10.0.0.99"
        },
        headers=headers
    )

    target_id = create_response.json()["id"]

    # Delete target
    delete_response = client.delete(f"/api/targets/{target_id}", headers=headers)
    assert delete_response.status_code == 204

    # Verify deleted
    get_response = client.get(f"/api/targets/{target_id}", headers=headers)
    assert get_response.status_code == 404
