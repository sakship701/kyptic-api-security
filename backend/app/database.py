from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DATABASE_URL = f"sqlite:///{Path(__file__).resolve().parents[1] / 'kyptic.db'}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def update_db_schema() -> None:
    inspector = inspect(engine)
    if "projects" in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('projects')]
        with engine.begin() as conn:
            if "source_type" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN source_type VARCHAR(50)"))
            if "source_status" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN source_status VARCHAR(50) NOT NULL DEFAULT 'NOT_INGESTED'"))
            if "local_source_reference" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN local_source_reference VARCHAR(500)"))
            if "target_url" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN target_url VARCHAR(500)"))
            if "last_ingested_at" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN last_ingested_at DATETIME"))
            if "ingestion_error" not in columns:
                conn.execute(text("ALTER TABLE projects ADD COLUMN ingestion_error TEXT"))

    if "scans" in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('scans')]
        with engine.begin() as conn:
            if "scanner" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN scanner VARCHAR(50)"))
            if "scanner_version" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN scanner_version VARCHAR(50)"))
            if "sca_status" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN sca_status VARCHAR(50)"))
            if "dast_status" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN dast_status VARCHAR(50)"))
            if "duration" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN duration FLOAT"))
            if "result_count" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN result_count INTEGER"))

    if "findings" in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('findings')]
        with engine.begin() as conn:
            if "rule_id" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN rule_id VARCHAR(255)"))
            if "cwe" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN cwe VARCHAR(255)"))
            if "owasp" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN owasp VARCHAR(255)"))
            if "end_line_number" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN end_line_number INTEGER"))
            if "code_snippet" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN code_snippet TEXT"))
            if "scanner_name" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN scanner_name VARCHAR(50)"))
            if "scanner_version" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN scanner_version VARCHAR(50)"))
            if "fingerprint" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(500)"))
            if "resolution_comment" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN resolution_comment TEXT"))
            if "resolved_at" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN resolved_at DATETIME"))