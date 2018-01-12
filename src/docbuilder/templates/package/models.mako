## Copyright (C) 2018 Google Inc.
## Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

.. WARNING! This file is autogenerated and should not be edited manually.

Models
======

% for model in package.models:
${h.title('``%s``' % model.obj.__name__, '-')}

..  class:: ${model.name}

    ${h.doc(model, 4)}

    Schema:

    ..  code-block:: sql

        ${h.textblock(model.create_table, 8)}

    Mixins:

    % for mixin in model.mixins:
    *   :class:`${mixin.name}`
    % endfor


% endfor
