from pathlib import Path
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database import DATABASE_URL, SessionLocal
from app.models.project import Project


def test_database_url_is_isolated():
    """Verify that pytest is running against isolated test_kyptic.db and NOT production kyptic.db."""
    dev_db_path = str((Path(__file__).resolve().parents[1] / "kyptic.db").resolve())
    test_db_url = str(DATABASE_URL)

    assert "test_kyptic.db" in test_db_url or ":memory:" in test_db_url
    assert "kyptic.db" not in test_db_url or "test_kyptic.db" in test_db_url


def test_test_db_operations_do_not_affect_production_db():
    """
    Regression Test:
    Verify that DB operations (insert, delete, query) performed by pytest operate
    strictly on the test DB and do NOT mutate the production/development kyptic.db.
    """
    dev_db_file = (Path(__file__).resolve().parents[1] / "kyptic.db").resolve()

    # 1. Perform write and delete operations in test database via SessionLocal
    test_session = SessionLocal()
    test_project = Project(name="Test Isolated Sentinel Project", technology="Python")
    test_session.add(test_project)
    test_session.commit()
    test_project_id = test_project.id

    # Verify sentinel project exists in test DB
    test_projects = test_session.scalars(select(Project).filter(Project.id == test_project_id)).all()
    assert len(test_projects) == 1

    test_session.query(Project).filter(Project.id == test_project_id).delete()
    test_session.commit()
    test_session.close()

    # 2. Inspect real development DB file directly without altering it
    if dev_db_file.exists():
        dev_engine = create_engine(f"sqlite:///{dev_db_file}")
        dev_session_factory = sessionmaker(bind=dev_engine)
        dev_session = dev_session_factory()
        try:
            # Query dev DB: Sentinel project must NEVER exist in production/dev DB
            dev_projects = dev_session.scalars(select(Project).filter(Project.name == "Test Isolated Sentinel Project")).all()
            assert len(dev_projects) == 0
        finally:
            dev_session.close()
            dev_engine.dispose()
