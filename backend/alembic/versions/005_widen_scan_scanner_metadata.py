"""Widen scanner and scanner_version columns in scans table

Revision ID: 005_widen_scan_scanner_metadata
Revises: 004_add_user_sessions
Create Date: 2026-10-06 22:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '005_widen_scan_scanner_metadata'
down_revision: Union[str, None] = '004_add_user_sessions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('scans') as batch_op:
        batch_op.alter_column(
            'scanner',
            existing_type=sa.String(length=50),
            type_=sa.String(length=255),
            existing_nullable=True,
        )
        batch_op.alter_column(
            'scanner_version',
            existing_type=sa.String(length=50),
            type_=sa.String(length=255),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table('scans') as batch_op:
        batch_op.alter_column(
            'scanner_version',
            existing_type=sa.String(length=255),
            type_=sa.String(length=50),
            existing_nullable=True,
        )
        batch_op.alter_column(
            'scanner',
            existing_type=sa.String(length=255),
            type_=sa.String(length=50),
            existing_nullable=True,
        )
