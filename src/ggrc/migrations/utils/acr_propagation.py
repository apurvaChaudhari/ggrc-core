# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Module with helpers for creating propagation access control roles."""

import datetime

import sqlalchemy as sa

from alembic import op


ACR_TABLE = sa.sql.table(
    "access_control_roles",
    sa.sql.column('id', sa.Integer),
    sa.sql.column('name', sa.String),
    sa.sql.column('object_type', sa.String),
    sa.sql.column('tooltip', sa.String),
    sa.sql.column('read', sa.Boolean),
    sa.sql.column('update', sa.Boolean),
    sa.sql.column('delete', sa.Boolean),
    sa.sql.column('my_work', sa.Boolean),
    sa.sql.column('created_at', sa.DateTime),
    sa.sql.column('modified_by_id', sa.Integer),
    sa.sql.column('updated_at', sa.DateTime),
    sa.sql.column('context_id', sa.Integer),
    sa.sql.column('internal', sa.Integer),
    sa.sql.column('non_editable', sa.Boolean),
    sa.sql.column('notify_about_proposal', sa.Integer),
    sa.sql.column('parent_id', sa.Integer),
)

ACL_TABLE = sa.sql.table(
    "access_control_list",
    sa.sql.column('id', sa.Integer),
    sa.sql.column('ac_role_id', sa.String),
)


def _parse_object_data(object_data):
  """Parse object data for role propagation.

  Examples:
    "Comment RU" > "Comment", {"read": True, "update": True, "delete": False}
    "Assessment" > "Assessment", {}

  Args:
    object_data: String containing object_type and permission data

  Returns:
    string for object type and dictionary for permissions data.
  """
  permission_flag_map = {
      "R": "read",
      "U": "update",
      "D": "delete",
      "M": "my_work",
  }
  permissions = {
      "read": False,
      "update": False,
      "delete": False,
      "my_work": False,
  }

  data = object_data.split()
  assert len(data) == 2
  object_type, permission_flags = data

  for flag in permission_flags:
    permissions[permission_flag_map[flag]] = True
  return object_type, permissions


def _add_subtree(tree, role_name, parent_id, with_update):
  """Add propagated roles for the given tree.
  keys of the tree must contain object data in form of "object_type RUD"
  strings or a list of those strings.
  """
  connection = op.get_bind()
  role_name = "{}*{}*".format(role_name.rstrip("*"), parent_id)
  for object_data_list, subtree in tree.items():
    if isinstance(object_data_list, basestring):
      object_data_list = [object_data_list]
    for object_data in object_data_list:
      object_type, permissions_dict = _parse_object_data(object_data)

      acr = None
      if with_update:
        acr = _get_acr(object_type, role_name)

      if not acr:
        insert = connection.execute(
            ACR_TABLE.insert().values(
                name=role_name,
                object_type=object_type,
                parent_id=parent_id,
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow(),
                internal=True,
                non_editable=True,
                **permissions_dict
            )
        )

      _add_subtree(subtree,
                   role_name,
                   acr.id if acr else insert.lastrowid,
                   with_update)


def _get_acr(object_type, name):
  """Get access control entry for a given role on object."""
  connection = op.get_bind()
  return connection.execute(
      ACR_TABLE.select().where(
          sa.and_(
              ACR_TABLE.c.name == name,
              ACR_TABLE.c.object_type == object_type,
          )
      )
  ).fetchone()


def _propagate_object_roles(object_type, roles_tree, with_update):
  """Propagate roles in the role tree for a given object type.

  The role propagation rules are given in the following format:
  {
      <role_name> | <iterable role_names>: {
          "<sub_type> <rights>": {
              "<sub_type> <rights>": {
                  ...
              },
          },
          ...
      }
  }

  Where:
    <sub_type> is a class name of a directly linked object for the object_type.
    <rights> is a subset of RUD representing flags for read update and delete.

  Args:
    object_type: Class name of the object for which we want to propagate roles.
    roles_tree: a dictionary with the role propagation rules.
  """
  for role_names, propagation_tree in roles_tree.items():
    if isinstance(role_names, basestring):
      role_names = [role_names]

    for role_name in role_names:
      role = _get_acr(object_type, role_name)
      _add_subtree(propagation_tree, role.name, role.id, with_update)


def propagate_roles(propagation_rules, with_update=False):
  for object_type, roles_tree in propagation_rules.items():
    _propagate_object_roles(object_type, roles_tree, with_update)


def remove_propagated_roles(object_type, role_names):
  """Remove propagated roles.
  Args:
    object_type: type of object for role deletion.
    role_names: list of role names for the given object type whose propagations
      we wish to delete.
  """
  names = set()
  for names_ in role_names:
    if isinstance(names_, basestring):
      names.add(names_)
    else:
      names.update(set(names_))
  connection = op.get_bind()
  parent_role_ids = sa.select([ACR_TABLE.c.id]).where(
      sa.and_(
          ACR_TABLE.c.name.in_(names),
          ACR_TABLE.c.object_type == object_type,
      )
  )
  child_role_ids = connection.execute(
      sa.select([ACR_TABLE.c.id]).where(
          ACR_TABLE.c.parent_id.in_(parent_role_ids),
      )
  ).fetchall()
  child_ids = [row.id for row in child_role_ids]
  if not child_ids:
    return
  op.execute(
      ACL_TABLE.delete().where(
          ACL_TABLE.c.ac_role_id.in_(child_ids)
      )
  )
  op.execute(
      ACR_TABLE.delete().where(
          ACR_TABLE.c.id.in_(child_ids)
      )
  )


def remove_deprecated_roles(role_names):
  """Remove old propagation roles.
  This should be used for previous propagation roles ending with keyword
  Mapped.
  """
  op.execute(
      ACL_TABLE.delete().where(
          ACL_TABLE.c.ac_role_id.in_(
              sa.select([ACR_TABLE.c.id]).where(
                  sa.and_(
                      ACR_TABLE.c.name.in_(role_names),
                      ACR_TABLE.c.internal == 1,
                  )
              )
          )
      )
  )
  op.execute(ACR_TABLE.delete().where(
          sa.and_(
              ACR_TABLE.c.name.in_(role_names),
              ACR_TABLE.c.internal == 1,
          )
      )
  )


def update_acr_propagation_tree(old_tree, new_tree):
  """Remove old tree and create new based on rules"""
  for object_type, roles_tree in old_tree.items():
    remove_propagated_roles(object_type, roles_tree.keys())
  propagate_roles(new_tree)
