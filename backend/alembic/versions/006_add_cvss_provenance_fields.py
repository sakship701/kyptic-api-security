"""Add cvss_vector, cvss_source, and cvss_version to findings table

Revision ID: 006_add_cvss_provenance_fields
Revises: 005_widen_scan_scanner_metadata
Create Date: 2026-10-07 18:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '006_add_cvss_provenance_fields'
down_revision: Union[str, None] = '005_widen_scan_scanner_metadata'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('cvss_vector', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('cvss_source', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('cvss_version', sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_column('cvss_version')
        batch_op.drop_column('cvss_source')
        batch_op.drop_column('cvss_vector')
