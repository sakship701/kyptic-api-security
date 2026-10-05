"""Initial Kyptic Database Schema Migration

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-09-24 22:24:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)

    # 2. Organizations table
    op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_organizations_id'), 'organizations', ['id'], unique=False)
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    # 3. Organization Members table
    op.create_table(
        'organization_members',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='member'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_organization_members_id'), 'organization_members', ['id'], unique=False)

    # 4. Projects table
    op.create_table(
        'projects',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('repository_url', sa.String(length=500), nullable=True),
        sa.Column('technology', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=True),
        sa.Column('source_status', sa.String(length=50), nullable=False, server_default='NOT_INGESTED'),
        sa.Column('local_source_reference', sa.String(length=500), nullable=True),
        sa.Column('target_url', sa.String(length=500), nullable=True),
        sa.Column('last_ingested_at', sa.DateTime(), nullable=True),
        sa.Column('ingestion_error', sa.Text(), nullable=True),
        sa.Column('api_target_url', sa.String(length=500), nullable=True),
        sa.Column('api_dast_enabled', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('api_auth_type', sa.String(length=50), nullable=True, server_default='NONE'),
        sa.Column('api_auth_header_name', sa.String(length=100), nullable=True, server_default='Authorization'),
        sa.Column('api_auth_token_hash', sa.String(length=255), nullable=True),
    )
    op.create_index(op.f('ix_projects_id'), 'projects', ['id'], unique=False)

    # 5. Scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='queued'),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_phase', sa.String(length=100), nullable=False, server_default='Queued'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('scanner', sa.String(length=50), nullable=True),
        sa.Column('scanner_version', sa.String(length=50), nullable=True),
        sa.Column('sca_status', sa.String(length=50), nullable=True),
        sa.Column('dast_status', sa.String(length=50), nullable=True),
        sa.Column('duration', sa.Float(), nullable=True),
        sa.Column('result_count', sa.Integer(), nullable=True),
    )
    op.create_index(op.f('ix_scans_id'), 'scans', ['id'], unique=False)
    op.create_index(op.f('ix_scans_project_id'), 'scans', ['project_id'], unique=False)

    # 6. Findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('scan_id', sa.Integer(), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('cvss', sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column('category', sa.String(length=255), nullable=False),
        sa.Column('file_path', sa.String(length=500), nullable=False),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='open'),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('rule_id', sa.String(length=255), nullable=True),
        sa.Column('cwe', sa.String(length=255), nullable=True),
        sa.Column('owasp', sa.String(length=255), nullable=True),
        sa.Column('end_line_number', sa.Integer(), nullable=True),
        sa.Column('code_snippet', sa.Text(), nullable=True),
        sa.Column('scanner_name', sa.String(length=50), nullable=True, server_default='semgrep'),
        sa.Column('scanner_version', sa.String(length=50), nullable=True),
        sa.Column('fingerprint', sa.String(length=500), nullable=True),
        sa.Column('resolution_comment', sa.Text(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('confidence_score', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('confidence_level', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('verification_status', sa.String(length=50), nullable=False, server_default='UNVERIFIED'),
        sa.Column('verification_explanation', sa.Text(), nullable=True),
        sa.Column('evidence_sources', sa.String(length=500), nullable=True),
        sa.Column('correlation_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('correlated_finding_ids', sa.Text(), nullable=True),
    )
    op.create_index(op.f('ix_findings_fingerprint'), 'findings', ['fingerprint'], unique=False)
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)
    op.create_index(op.f('ix_findings_project_id'), 'findings', ['project_id'], unique=False)
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'], unique=False)

    # 7. API Endpoints table
    op.create_table(
        'api_endpoints',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('path', sa.String(length=500), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('summary', sa.String(length=500), nullable=True),
        sa.Column('operation_id', sa.String(length=255), nullable=True),
        sa.Column('auth_status', sa.String(length=50), nullable=False, server_default='UNAUTHENTICATED'),
        sa.Column('auth_type', sa.String(length=50), nullable=True, server_default='NONE'),
        sa.Column('rate_limit_status', sa.String(length=50), nullable=False, server_default='MISSING'),
        sa.Column('request_validation_status', sa.String(length=50), nullable=False, server_default='UNCONSTRAINED'),
        sa.Column('sensitive_data_fields', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_level', sa.String(length=20), nullable=False, server_default='INFO'),
        sa.Column('bola_status', sa.String(length=50), nullable=False, server_default='NONE'),
        sa.Column('mass_assignment_status', sa.String(length=50), nullable=False, server_default='NONE'),
        sa.Column('dast_status', sa.String(length=50), nullable=False, server_default='UNTESTED'),
        sa.Column('discovered_via', sa.String(length=50), nullable=False, server_default='OPENAPI_SPEC'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_api_endpoints_id'), 'api_endpoints', ['id'], unique=False)
    op.create_index(op.f('ix_api_endpoints_project_id'), 'api_endpoints', ['project_id'], unique=False)

    # 8. Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('organization_id', sa.Integer(), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('api_endpoints')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('projects')
    op.drop_table('organization_members')
    op.drop_table('organizations')
    op.drop_table('users')
