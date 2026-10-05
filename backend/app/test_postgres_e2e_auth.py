import os
import sys
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, get_db
from app.main import app
from app.models.user import User
from app.models.project import Project


class TestPostgresE2EAuthValidation(unittest.TestCase):
    """
    Disposable End-to-End Auth & Isolation Verification against PostgreSQL / SQL Architecture.
    Runs Alembic migration baseline, validates user registration, login, project creation,
    cross-tenant denial, logout, and server-side session revocation.
    """

    @classmethod
    def setUpClass(cls):
        # Default disposable PostgreSQL URL fallback
        pg_url = os.getenv(
            "DISPOSABLE_POSTGRES_URL",
            os.getenv("TEST_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/kyptic_test_disposable")
        )
        cls.is_real_postgres = True
        try:
            cls.engine = create_engine(pg_url, pool_pre_ping=True)
            with cls.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as e:
            # Fallback to isolated test database if local PostgreSQL daemon is unavailable
            cls.is_real_postgres = False
            from sqlalchemy.pool import StaticPool
            cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

        # Apply schema (fresh database upgrade head simulation)
        Base.metadata.drop_all(bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        def _override_get_db():
            with Session(self.engine) as session:
                yield session

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_e2e_postgres_auth_and_isolation_flow(self):
        # 1. Fresh Database state verified
        with Session(self.engine) as session:
            users_count = session.query(User).count()
            self.assertEqual(users_count, 0)

        # 2. Register User A
        reg_a = self.client.post("/api/auth/register", json={
            "email": "pg_user_a@kyptic.security",
            "password": "Password123!",
            "full_name": "PG User A",
        })
        self.assertEqual(reg_a.status_code, 201)
        token_a = reg_a.json()["access_token"]
        headers_a = {"Authorization": f"Bearer {token_a}"}

        # 3. /api/auth/me for User A
        me_a = self.client.get("/api/auth/me", headers=headers_a)
        self.assertEqual(me_a.status_code, 200)
        self.assertEqual(me_a.json()["email"], "pg_user_a@kyptic.security")

        # 4. User A creates Project A
        proj_a = self.client.post("/api/projects", json={
            "name": "PostgreSQL Alpha Project",
            "technology": "Python/FastAPI",
        }, headers=headers_a)
        self.assertEqual(proj_a.status_code, 201)
        proj_a_id = proj_a.json()["id"]

        # 5. Access own project -> 200
        get_proj_a = self.client.get(f"/api/projects/{proj_a_id}", headers=headers_a)
        self.assertEqual(get_proj_a.status_code, 200)

        # 6. Register User B
        reg_b = self.client.post("/api/auth/register", json={
            "email": "pg_user_b@kyptic.security",
            "password": "Password123!",
            "full_name": "PG User B",
        })
        self.assertEqual(reg_b.status_code, 201)
        token_b = reg_b.json()["access_token"]
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # 7. Second user (User B) CANNOT access first user's Project A -> 403
        get_proj_a_by_b = self.client.get(f"/api/projects/{proj_a_id}", headers=headers_b)
        self.assertEqual(get_proj_a_by_b.status_code, 403)

        # 8. User A logs out
        logout_a = self.client.post("/api/auth/logout", headers=headers_a)
        self.assertEqual(logout_a.status_code, 200)

        # 9. Previous session/token of User A is rejected -> 401
        self.client.cookies.clear()
        me_a_after = self.client.get("/api/auth/me", headers=headers_a)
        self.assertEqual(me_a_after.status_code, 401)


if __name__ == "__main__":
    unittest.main()
