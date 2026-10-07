"""Enforce Single User Role and Deprecate Superuser Privileges

Revision ID: 003_enforce_single_user_role
Revises: 002_add_user_project_ownership
Create Date: 2026-09-29 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_enforce_single_user_role'
down_revision: Union[str, None] = '002_add_user_project_ownership'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Kyptic operates strictly on ONE application role: User.
    # We ensure is_superuser defaults to False across any existing records.
    users = sa.table(
        'users',
        sa.column('is_superuser', sa.Boolean())
    )
    op.execute(
        users.update()
        .where(
            sa.or_(
                users.c.is_superuser.is_(None),
                users.c.is_superuser.is_(True),
            )
        )
        .values(is_superuser=False)
    )


def downgrade() -> None:
    pass
