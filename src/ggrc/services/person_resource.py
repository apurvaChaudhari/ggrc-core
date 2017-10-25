# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Resource for handling special endpoints for people."""

import datetime

from werkzeug.exceptions import Forbidden

from ggrc import db
from ggrc.login import get_current_user_id
from ggrc.utils import benchmark
from ggrc.services import common


class PersonResource(common.ExtendedResource):
  """Resource handler for people."""

  # method post is abstract and not used.
  # pylint: disable=abstract-method

  def get(self, *args, **kwargs):
    # This is to extend the get request for additional data.
    # pylint: disable=arguments-differ
    command_map = {
        None: super(PersonResource, self).get,
        "task_count": self._task_count,
    }
    command = kwargs.pop("command", None)
    if command not in command_map:
      self.not_found_response()
    return command_map[command](*args, **kwargs)

  def _task_count(self, id):
    """Return open task count and overdue flag for a given user."""
    # id name is used as a kw argument and can't be changed here
    # pylint: disable=invalid-name,redefined-builtin

    if id != get_current_user_id():
      raise Forbidden()
    with benchmark("Make response"):
      # query below ignores acr.read flag because this is done on a
      # non_editable role that has read rights:
      counts_query = db.session.execute(
          """
          SELECT
              overdue,
              sum(task_count)
          FROM (
              SELECT
                  ct.end_date < :today AS overdue,
                  count(ct.id) AS task_count
              FROM cycle_task_group_object_tasks AS ct
              JOIN cycles AS c ON
                  c.id = ct.cycle_id
              JOIN access_control_list AS acl
                  ON acl.object_id = ct.id
                  AND acl.object_type = "CycleTaskGroupObjectTask"
              JOIN access_control_roles as acr
                  ON acl.ac_role_id = acr.id
              WHERE
                  ct.status != "Verified" AND
                  c.is_verification_needed = 1 AND
                  c.is_current = 1 AND
                  acl.person_id = :person_id AND
                  acr.name = "Task Assignees"
              GROUP BY overdue

              UNION ALL

              SELECT
                  ct.end_date < :today AS overdue,
                  count(ct.id) AS task_count
              FROM cycle_task_group_object_tasks AS ct
              JOIN cycles AS c ON
                  c.id = ct.cycle_id
              JOIN access_control_list AS acl
                  ON acl.object_id = ct.id
                  AND acl.object_type = "CycleTaskGroupObjectTask"
              JOIN access_control_roles as acr
                  ON acl.ac_role_id = acr.id
              WHERE
                  ct.status != "Finished" AND
                  c.is_verification_needed = 0 AND
                  c.is_current = 1 AND
                  acl.person_id = :person_id AND
                  acr.name = "Task Assignees"
              GROUP BY overdue
          ) as temp
          GROUP BY overdue
          """,
          {
              # Using today instead of DATE(NOW()) for easier testing with
              # freeze gun.
              "today": datetime.date.today(),
              "person_id": id,
          }
      )
      counts = dict(counts_query.fetchall())
      response_object = {
          "open_task_count": int(sum(counts.values())),
          "has_overdue": bool(counts.get(1, 0)),
      }
      return self.json_success_response(response_object, )
