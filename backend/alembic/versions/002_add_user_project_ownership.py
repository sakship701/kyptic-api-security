"""Add User Project Ownership Migration

Revision ID: 002_add_user_project_ownership
Revises: 001_initial_schema
Create Date: 2026-09-29 20:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_add_user_project_ownership'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add user_id column to projects table to support direct user ownership
    op.add_column('projects', sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True))
    op.create_index(op.f('ix_projects_user_id'), 'projects', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_projects_user_id'), table_name='projects')
    op.drop_column('projects', 'user_id')
