"""Add User Sessions Table for Server-Side Revocation

Revision ID: 004_add_user_sessions
Revises: 003_enforce_single_user_role
Create Date: 2026-10-05 17:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004_add_user_sessions'
down_revision: Union[str, None] = '003_enforce_single_user_role'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('jti', sa.String(length=64), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_id'), 'user_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_sessions_jti'), 'user_sessions', ['jti'], unique=True)
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_user_sessions_expires_at'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_jti'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_id'), table_name='user_sessions')
    op.drop_table('user_sessions')
