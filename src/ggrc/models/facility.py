# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

from ggrc import db
from ggrc.access_control.roleable import Roleable
from ggrc.fulltext.mixin import Indexed
from ggrc.models.comment import ScopedCommentable
from ggrc.models import mixins
from ggrc.models.object_document import PublicDocumentable
from ggrc.models.object_person import Personable
from ggrc.models.relationship import Relatable
from ggrc.models.track_object_state import HasObjectState


class Facility(Roleable,
               HasObjectState,
               PublicDocumentable,
               mixins.CustomAttributable,
               Personable,
               Relatable,
               ScopedCommentable,
               mixins.TestPlanned,
               mixins.LastDeprecatedTimeboxed,
               mixins.base.ContextRBAC,
               mixins.BusinessObject,
               mixins.Folderable,
               Indexed,
               db.Model):
  __tablename__ = 'facilities'
  _aliases = {
      "documents_file": None,
  }
