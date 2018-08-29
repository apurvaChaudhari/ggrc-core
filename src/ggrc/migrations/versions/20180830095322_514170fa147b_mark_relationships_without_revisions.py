# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""
Mark relationships without revisions

Create Date: 2018-08-30 09:53:22.215364
"""
# disable Invalid constant name pylint warning for mandatory Alembic variables.
# pylint: disable=invalid-name

from alembic import op


# revision identifiers, used by Alembic.
revision = '514170fa147b'
down_revision = 'c3ef0656a527'


def upgrade():
  """Mark relationships without revisions for new revision creation."""

  op.execute("""
      insert ignore into objects_without_revisions (
          obj_id,
          obj_type,
          action
      )
      select
          id,
          "Relationship",
          "Created"
      from relationships
      where
        id not in (
          select resource_id
          from revisions
          where resource_type = "Relationship"
        )
  """)


def downgrade():
  """We never delete revisions so downgrade can be ignored."""
