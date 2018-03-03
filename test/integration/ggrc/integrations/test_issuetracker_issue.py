# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Integration test for Clonable mixin"""

from mock import patch

from ggrc import db
from ggrc import models
from ggrc.models import all_models
from ggrc.models.hooks import issue_tracker
from ggrc.integrations import issues as issues_module
from ggrc.integrations import utils

from integration.ggrc.models import factories
from integration.ggrc import generator
from integration.ggrc.access_control import acl_helper
from integration.ggrc.snapshotter import SnapshotterBaseTestCase


class TestIssueTrackerIntegration(SnapshotterBaseTestCase):

  """Test set for IssueTracker integration functionality"""

  # pylint: disable=invalid-name

  def setUp(self):
    # pylint: disable=super-on-old-class
    # pylint seems to get confused, mro chain successfully resolves and returns
    # <type 'object'> as last entry.
    super(TestIssueTrackerIntegration, self).setUp()

    self.client.get("/login")

  # pylint: disable=unused-argument
  @patch('ggrc.integrations.issues.Client.update_issue')
  def test_update_issuetracker_info(self, mock_update_issue):
    """Test that issuetracker issues are updated by the utility"""
    with patch.object(issue_tracker, '_is_issue_tracker_enabled',
                      return_value=True):
      iti_issue_id = []
      for _ in range(2):
        iti = factories.IssueTrackerIssueFactory()
        iti_issue_id.append(iti.issue_id)
        asmt = iti.issue_tracked_obj
        asmt_id = asmt.id
        audit = asmt.audit
        self.api.modify_object(audit, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
            },
        })
        asmt = db.session.query(models.Assessment).get(asmt_id)
        self.api.modify_object(asmt, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
            },
        })
        asmt = db.session.query(models.Assessment).get(asmt_id)
        self.api.modify_object(asmt, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
                "issue_priority": "P4",
                "issue_severity": "S3",
            },
        })
      self.api.delete(asmt)
      with patch.object(issues_module.Client, 'update_issue',
                        return_value=None) as mock_method:
        utils.sync_issue_tracker_statuses()
        mock_method.assert_called_once_with(iti_issue_id[0],
                                            {'status': 'ASSIGNED',
                                             'priority': u'P4',
                                             'type': None,
                                             'severity': u'S3'})


@patch("ggrc.models.hooks.issue_tracker._is_issue_tracker_enabled",
       return_value=True)
@patch("ggrc.integrations.issues.Client")
class TestIssueTrackerIntegrationPeople(SnapshotterBaseTestCase):
  """Test people used in IssueTracker Issues."""

  EMAILS = {
      "Audit Captains": {"audit_captain_1@example.com",
                         "audit_captain_2@example.com"},
      "Auditors": {"auditor_1@example.com", "auditor_2@example.com"},
      "Creators": {"creator_1@example.com", "creator_2@example.com"},
      "Assignees": {"assignee_1@example.com", "assignee_2@example.com"},
      "Verifiers": {"verifier_1@example.com", "verifier_2@example.com"},
  }

  def setUp(self):
    super(TestIssueTrackerIntegrationPeople, self).setUp()
    self.generator = generator.ObjectGenerator()

    # fetch all roles mentioned in self.EMAILS
    self.roles = {
        role.name: role
        for role in all_models.AccessControlRole.query.filter(
            all_models.AccessControlRole.name.in_(
                self.EMAILS.keys(),
            ),
        )
    }

    with factories.single_commit():
      self.audit = factories.AuditFactory()

      self.people = {
          role_name: [factories.PersonFactory(email=email)
                      for email in emails]
          for role_name, emails in self.EMAILS.iteritems()
      }

      for role_name in ("Audit Captains", "Auditors"):
        role = self.roles[role_name]
        for person in self.people[role_name]:
          factories.AccessControlListFactory(person=person,
                                             ac_role=role,
                                             object=self.audit)

  def test_new_assessment_people(self, client_mock, _):
    client_instance = client_mock.return_value
    client_instance.create_issue.return_value = {"issueId": 42}

    access_control_list = acl_helper.get_acl_list({
        person.id: self.roles[role_name].id
        for role_name, people in self.people.iteritems()
        for person in people
        if role_name in ("Creators", "Assignees", "Verifiers")
    })
    component_id = hash("Component id")
    hotlist_id = hash("Hotlist id")
    issue_type = "Issue type"
    issue_priority = "Issue priority"
    issue_severity = "Issue severity"

    _, asmt = self.generator.generate_object(
        all_models.Assessment,
        data={
            "issue_tracker": {
                "enabled": True,
                "component_id": component_id,
                "hotlist_id": hotlist_id,
                "issue_type": issue_type,
                "issue_priority": issue_priority,
                "issue_severity": issue_severity,
            },
            "audit": {"id": self.audit.id, "type": self.audit.type},
            "access_control_list": access_control_list,
        }
    )

    expected_cc_list = list(
        self.EMAILS["Assignees"] - {min(self.EMAILS["Assignees"])}
    )

    client_instance.create_issue.assert_called_once_with({
        # common fields
        "comment": (issue_tracker._INITIAL_COMMENT_TMPL %
                    issue_tracker._get_assessment_url(asmt)),
        "component_id": component_id,
        "hotlist_ids": [hotlist_id],
        "priority": issue_priority,
        "severity": issue_severity,
        "status": "ASSIGNED",
        "title": asmt.title,
        "type": issue_type,

        # person-related fields
        "reporter": min(self.EMAILS["Audit Captains"]),
        "assignee": min(self.EMAILS["Assignees"]),
        "verifier": min(self.EMAILS["Assignees"]),
        "ccs": expected_cc_list,
    })
