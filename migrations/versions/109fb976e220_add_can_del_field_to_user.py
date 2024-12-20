"""Add can_del field to User

Revision ID: 109fb976e220
Revises: a3ea5d4b480b
Create Date: 2024-11-07 16:20:16.252350

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '109fb976e220'
down_revision = 'a3ea5d4b480b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('can_del', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'can_del')
    # ### end Alembic commands ###
