from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.auth_service import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


@pytest.fixture(scope="module")
def auth_engine():
    """Isolated in-memory test database engine for auth tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def auth_db_session(auth_engine):
    """Session for test setup/assertions."""
    with Session(auth_engine) as session:
        yield session


@pytest.fixture
def client(auth_engine):
    """FastAPI TestClient with overridden database session."""
    def _override_get_db():
        with Session(auth_engine) as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# 1. Password Hashing & Verification Tests
def test_password_hashing_and_verification():
    raw_password = "SuperSecretPassword123!"
    hashed = hash_password(raw_password)

    # Must not be plaintext
    assert hashed != raw_password
    assert len(hashed) > 20

    # Verification success
    assert verify_password(raw_password, hashed) is True

    # Verification failure on wrong password
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw_password, "") is False
    assert verify_password(raw_password, "invalid_format_hash") is False


def test_password_hashing_empty_raises():
    with pytest.raises(ValueError):
        hash_password("")


# 2. Token Creation & Decoding Tests
def test_jwt_token_lifecycle():
    user_data = {"user_id": 42, "email": "test@kyptic.security"}
    token = create_access_token(user_data, expires_delta=timedelta(minutes=15))

    assert isinstance(token, str)
    assert len(token) > 20

    # Valid decode
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["user_id"] == 42
    assert payload["email"] == "test@kyptic.security"

    # Expired token decode returns None
    expired_token = create_access_token(user_data, expires_delta=timedelta(minutes=-5))
    assert decode_access_token(expired_token) is None

    # Malformed token returns None
    assert decode_access_token("malformed.jwt.token") is None
    assert decode_access_token("") is None


# 3. User Registration Endpoint Tests
def test_register_user_success(client, auth_db_session):
    payload = {
        "email": "alice@example.com",
        "password": "Password123!",
        "full_name": "Alice Morgan",
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "alice@example.com"
    assert data["user"]["full_name"] == "Alice Morgan"
    assert data["user"]["is_active"] is True
    # Ensure sensitive fields are NEVER exposed
    assert "password" not in data["user"]
    assert "password_hash" not in data["user"]

    # Cookie is set
    assert "kyptic_session" in response.cookies

    # User exists in DB and password is hashed
    user = auth_db_session.scalar(select(User).where(User.email == "alice@example.com"))
    assert user is not None
    assert user.password_hash != "Password123!"
    assert verify_password("Password123!", user.password_hash) is True

    # Audit log entry created
    audit = auth_db_session.scalar(select(AuditLog).where(AuditLog.action == "USER_REGISTER"))
    assert audit is not None
    assert audit.user_id == user.id


def test_register_duplicate_email_fails(client):
    payload = {
        "email": "duplicate@example.com",
        "password": "Password123!",
        "full_name": "Duplicate User",
    }
    res1 = client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    # Second registration with same email must fail
    res2 = client.post("/api/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"].lower()


def test_register_invalid_inputs(client):
    # Short password (<8 chars)
    res = client.post("/api/auth/register", json={
        "email": "short@example.com",
        "password": "short",
    })
    assert res.status_code == 422

    # Invalid email format
    res = client.post("/api/auth/register", json={
        "email": "not-an-email",
        "password": "Password123!",
    })
    assert res.status_code == 422


# 4. User Login Endpoint Tests
def test_login_user_success_and_failure(client, auth_db_session):
    # Register user first
    reg_payload = {
        "email": "bob@example.com",
        "password": "SecurePassword999!",
        "full_name": "Bob Vance",
    }
    client.post("/api/auth/register", json=reg_payload)

    # Valid Login
    login_payload = {
        "email": "bob@example.com",
        "password": "SecurePassword999!",
    }
    login_res = client.post("/api/auth/login", json=login_payload)
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["user"]["email"] == "bob@example.com"
    assert "kyptic_session" in login_res.cookies

    # Invalid Password Login
    bad_login_res = client.post("/api/auth/login", json={
        "email": "bob@example.com",
        "password": "WrongPassword123!",
    })
    assert bad_login_res.status_code == 401
    assert "invalid email or password" in bad_login_res.json()["detail"].lower()

    # Nonexistent user login
    no_user_res = client.post("/api/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "SomePassword123!",
    })
    assert no_user_res.status_code == 401


def test_login_deactivated_user(client, auth_db_session):
    reg_payload = {
        "email": "inactive@example.com",
        "password": "Password123!",
    }
    client.post("/api/auth/register", json=reg_payload)

    # Deactivate user in DB
    user = auth_db_session.scalar(select(User).where(User.email == "inactive@example.com"))
    user.is_active = False
    auth_db_session.commit()

    login_res = client.post("/api/auth/login", json=reg_payload)
    assert login_res.status_code == 401
    assert "deactivated" in login_res.json()["detail"].lower()


# 5. Current User (/api/auth/me) Tests
def test_get_me_authenticated_and_unauthenticated(client):
    # Unauthenticated request -> 401
    res = client.get("/api/auth/me")
    assert res.status_code == 401

    # Register and get token
    reg_res = client.post("/api/auth/register", json={
        "email": "charlie@example.com",
        "password": "Password123!",
        "full_name": "Charlie Chaplin",
    })
    token = reg_res.json()["access_token"]

    # Authenticated via Bearer Header
    auth_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert auth_res.status_code == 200
    user_data = auth_res.json()
    assert user_data["email"] == "charlie@example.com"
    assert user_data["full_name"] == "Charlie Chaplin"
    assert "password_hash" not in user_data


# 6. Logout & Server-Side Session Revocation Tests
def test_logout_user_and_session_revocation(client, auth_db_session):
    client.cookies.clear()
    reg_res = client.post("/api/auth/register", json={
        "email": "david@example.com",
        "password": "Password123!",
    })
    token = reg_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Authenticated request BEFORE logout works
    me_res_before = client.get("/api/auth/me", headers=headers)
    assert me_res_before.status_code == 200
    assert me_res_before.json()["email"] == "david@example.com"

    # 2. Perform Logout
    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out."

    # 3. Authenticated request AFTER logout using same token fails (401 Revoked)
    client.cookies.clear()
    me_res_after = client.get("/api/auth/me", headers=headers)
    assert me_res_after.status_code == 401
    assert "revoked" in me_res_after.json()["detail"].lower() or "expired" in me_res_after.json()["detail"].lower()


def test_expired_session_rejected(client, auth_db_session):
    client.cookies.clear()
    reg_res = client.post("/api/auth/register", json={
        "email": "eve@example.com",
        "password": "Password123!",
    })
    user_id = reg_res.json()["user"]["id"]

    # Issue an expired token/session (-10 minutes)
    expired_token = create_access_token(
        {"user_id": user_id, "email": "eve@example.com"},
        expires_delta=timedelta(minutes=-10),
        db=auth_db_session,
    )
    headers = {"Authorization": f"Bearer {expired_token}"}

    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 401
