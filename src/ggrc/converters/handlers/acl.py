# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Handlers for access control roles."""

from ggrc import models
from ggrc.converters.handlers import handlers


class AccessControlRoleColumnHandler(handlers.UsersColumnHandler):
  """Handler for access control roles."""

  def __init__(self, row_converter, key, **options):
    super(AccessControlRoleColumnHandler, self).__init__(
        row_converter, key, **options)
    self.role = models.AccessControlRole.query.filter_by(
        name=self.display_name
    ).first()

  def _add_people(self, people_list):
    for person in people_list:
      models.AccessControlList(
          object=self.row_converter.obj,
          person=person,
          ac_role_id=self.role.id
      )

  def _remove_people(self, people_list):
    acl_email_map = {
        acl.person.email: acl
        for acl in self.row_converter.obj.access_control_list
    }
    for person in people_list:
      acl = acl_email_map[person.email]
      self.row_converter.obj.access_control_list.remove(acl)

  def set_obj_attr(self):
    if not self.value:
      return
    list_old = {i.person for i in self.row_converter.obj.access_control_list}
    list_new = set(self.value)

    self._add_people(list_new - list_old)
    self._remove_people(list_old - list_new)
