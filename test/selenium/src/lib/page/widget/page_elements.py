# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
"""Page objects for child elements of pages"""
# pylint: disable=too-few-public-methods
import datetime
import time

from lib.constants import objects
from lib.constants.element import AdminWidgetCustomAttributes
from lib.utils import selenium_utils, ui_utils


class InlineEdit(object):
  """Inline edit page element."""
  def __init__(self, root):
    self._root = root

  def open(self):
    """Opens inline edit."""
    # Hovering over element and clicking on it using Selenium / Nerodia
    # doesn't open the inline edit control for some reason
    self._root.wait_until_present()
    self._root.element(class_name="fa-pencil").js_click()

  def confirm(self):
    """Saves changes via inline edit."""
    save_btn = self._root.element(class_name="fa-check")
    save_btn.click()
    # Wait for inline edit element to be removed
    save_btn.wait_until_not(lambda e: e.exists)
    # Wait for JS to work, there are no DOM changes and HTTP requests
    # during some period (GGRC-5891).
    time.sleep(1)


class RelatedPeopleList(object):
  """Represents related people element"""

  def __init__(self, container, acr_name):
    self._root = container.element(
        class_name="people-group__title", text=acr_name).parent(
            class_name="people-group")
    self._inline_edit = InlineEdit(self._root)

  def add_person(self, person):
    """Add person to Related People list"""
    self._inline_edit.open()
    email = person.email
    self._root.text_field(placeholder="Add person").set(email)
    ui_utils.select_user(self._root, email)
    self._inline_edit.confirm()

  def get_people_emails(self):
    """Get emails of people"""
    return [el.text for el in self._root.elements(class_name="person-name")]


class RelatedUrls(object):
  """Represents reference / evidence url section on info widgets"""

  def __init__(self, container, label):
    self._root = container.element(
        class_name="related-urls__title", text=label).parent(
            class_name="related-urls")
    self.add_button = self._root.button(class_name="related-urls__toggle")


class AssessmentEvidenceUrls(object):
  """Represents assessment urls section on info widgets"""

  def __init__(self, container):
    self._root = container.element(
        class_name="info-pane__section-title", text="Evidence URL").parent()

  def add_url(self, url):
    """Add url"""
    self._root.button(text="Add").click()
    self._root.text_field(class_name="create-form__input").set(url)
    self._root.element(class_name="create-form__confirm").click()

  def get_urls(self):
    """Get urls"""
    return [el.text for el in self._root.elements(class_name="link")]


class CommentArea(object):
  """Represents comment area (form and mapped comments) on info widget"""

  def __init__(self, container):
    self.add_section = container.element(
        class_name="comment-add-form__section")


class EditPopup(object):
  """Represents edit popup."""

  def __init__(self, container):
    self.modal = container.element(class_name="modal-wide")

  def save_and_close(self):
    """Saves and closes edit popup."""
    self.modal.element(data_toggle="modal-submit").click()
    self.modal.wait_until_not_present()


class CustomAttributeManager(object):
  """Manager for custom attributes.
  It finds them based on object type, whether it is
  global / local, inline / popup.
  Also it provides access to overall operations like getting all titles.
  """

  def __init__(self, browser, obj_type, is_global, is_inline):
    self._browser = browser
    self.obj_type = obj_type
    self.is_global = is_global
    self.is_inline = is_inline
    self.all_labels = self._get_all_labels()

  def _get_all_labels(self):
    """Returns list of all labels."""
    if self.is_global:
      if not self.is_inline:
        elements = self._browser.element(
            tag_name="gca-controls").elements(
            class_name="ggrc-form-item__label-text")
      elif self.obj_type == objects.ASSESSMENTS:
        elements = self._browser.element(
            tag_name="assessment-custom-attributes").elements(
            class_name="ggrc-form__title")
      else:
        elements = self._browser.element(
            tag_name="global-custom-attributes").elements(
            class_name="info-pane__section-title")
    else:
      elements = self._browser.element(
          tag_name="assessment-local-ca").elements(
          class_name="field__title-text")
    return list(elements)

  def all_ca_titles(self):
    """Returns all CA titles."""
    return [el.text for el in self.all_labels]

  def find_ca_elem_by_title(self, title):
    """Finds CA page element based on title."""
    return CustomAttribute(title, self)


class CustomAttribute(object):
  """Custom attribute page element."""

  def __init__(self, title, ca_manager):
    self._ca_manager = ca_manager
    self._label_el = self._get_label_el(title)
    self._root = self._get_root(self._label_el)
    self._ca_strategy = {
        AdminWidgetCustomAttributes.TEXT: TextCAActionsStrategy,
        AdminWidgetCustomAttributes.RICH_TEXT: RichTextCAActionsStrategy,
        AdminWidgetCustomAttributes.DATE: DateCAActionsStrategy,
        AdminWidgetCustomAttributes.CHECKBOX: CheckboxCAActionsStrategy,
        AdminWidgetCustomAttributes.DROPDOWN: DropdownCAActionsStrategy,
        AdminWidgetCustomAttributes.PERSON: PersonCAActionsStrategy
    }[self.ca_type](self._root, self._label_el)

  def _get_label_el(self, title):
    """Finds label element by title."""
    return selenium_utils.filter_by_text(self._ca_manager.all_labels, title)

  def _get_root(self, label_el):
    """Finds root element of CA by label element."""
    if self._ca_manager.is_global:
      root_cls = "ggrc-form-item"
    else:
      root_cls = "field-wrapper flex-size-1"
    return label_el.parent(class_name=root_cls)

  @property
  def ca_type(self):
    """Returns type of CA element."""
    if self._ca_manager.is_global and self._ca_manager.is_inline:
      js_el = self._root.element(class_name="inline-edit-control")
    else:
      js_el = self._root.element(class_name="form-field__content")
    js_type = js_el.browser.execute_script(
        "return $(arguments[0]).viewModel().attr('type')", js_el)
    return {
        "input": AdminWidgetCustomAttributes.TEXT,
        "text": AdminWidgetCustomAttributes.RICH_TEXT,
        "date": AdminWidgetCustomAttributes.DATE,
        "checkbox": AdminWidgetCustomAttributes.CHECKBOX,
        "dropdown": AdminWidgetCustomAttributes.DROPDOWN,
        "person": AdminWidgetCustomAttributes.PERSON
    }[js_type]

  def get_value(self):
    """Gets value of custom attribute element."""
    if self._ca_manager.is_global:
      value = self._ca_strategy.get_gcas_from_inline()
    else:
      value = self._ca_strategy.get_lcas_from_inline()
    empty_string_strategies = (
        TextCAActionsStrategy, RichTextCAActionsStrategy,
        DropdownCAActionsStrategy)
    if isinstance(self._ca_strategy, empty_string_strategies) and value == "":
      return None
    elif (isinstance(self._ca_strategy, DateCAActionsStrategy) and
          value not in ("", "None")):
      value = value.split("/")
      return unicode("{y}-{m}-{d}".format(y=value[2], m=value[0], d=value[1]))
    return value

  def set_value(self, value):
    """Sets value for custom attribute element."""
    if self._ca_manager.is_inline:
      if self._ca_manager.is_global:
        self._ca_strategy.set_gcas_from_inline(value)
      else:
        self._ca_strategy.set_lcas_from_inline(value)
      # Wait for JS to work, there are no DOM changes and HTTP requests
      # during some period (GGRC-5891).
      time.sleep(1)
    else:
      self._ca_strategy.set_gcas_from_popup(value)


class CAActionsStrategy(object):
  """Parent class for custom attribute actions."""
  def __init__(self, root, label_el):
    self._root = root
    self._label_el = label_el
    self._inline_edit = InlineEdit(self._root)

  def get_gcas_from_inline(self):
    """Gets value of inline GCA field."""
    return self._root.element(class_name="inline__content").text

  def set_gcas_from_inline(self, value):
    """Sets value of inline GCA field."""
    self._inline_edit.open()
    self._fill_input_field(value)
    self._inline_edit.confirm()

  def set_gcas_from_popup(self, value):
    """Sets value of GCA field in popup."""
    self._fill_input_field(value)

  def _fill_input_field(self, value):
    """Fills input field."""
    raise NotImplementedError


class TextCAActionsStrategy(CAActionsStrategy):
  """Actions for Text CA."""

  def __init__(self, *args):
    super(TextCAActionsStrategy, self).__init__(*args)
    self._input = self._root.text_field(class_name="text-field")

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    return self._input.value

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    self._input.send_keys(value)
    self._label_el.click()

  def _fill_input_field(self, value):
    """Fills input field."""
    self._input.send_keys(value)


class RichTextCAActionsStrategy(CAActionsStrategy):
  """Actions for Rich text CA."""

  def __init__(self, *args):
    super(RichTextCAActionsStrategy, self).__init__(*args)
    self._input = self._root.element(class_name="ql-editor")

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    return self._input.text

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    self._input.send_keys(value)
    self._label_el.click()

  def _fill_input_field(self, value):
    """Fills input field."""
    self._input.send_keys(value)


class DateCAActionsStrategy(CAActionsStrategy):
  """Actions for Date CA."""

  def __init__(self, *args):
    super(DateCAActionsStrategy, self).__init__(*args)
    self._datepicker_field = self._root.element(class_name="datepicker__input")
    self._datepicker_opts = self._root.element(
        class_name="datepicker__calendar").elements(
        data_handler="selectDay")

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    return self._datepicker_field.value

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    self._select_date(value)

  def _fill_input_field(self, value):
    """Fills input field."""
    self._select_date(value)

  def _select_date(self, value):
    """Selects day in current month."""
    self._datepicker_field.click()
    self._datepicker_opts[
        datetime.datetime.strptime(value, "%Y-%m-%d").day - 1].click()


class CheckboxCAActionsStrategy(CAActionsStrategy):
  """Actions for Checkbox CA."""

  def __init__(self, *args):
    super(CheckboxCAActionsStrategy, self).__init__(*args)
    self._input = self._root.checkbox()

  def get_gcas_from_inline(self):
    """Gets value of inline GCA field."""
    return self._input.is_set

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    return self._input.is_set

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    # in case no action performed, status will not be changed
    # double click on checkbox equals to not checked
    self._input.click()
    self._input.set(value)

  def _fill_input_field(self, value):
    """Fills input field."""
    self._input.set(value)


class DropdownCAActionsStrategy(CAActionsStrategy):
  """Actions for Dropown CA."""

  def __init__(self, *args):
    super(DropdownCAActionsStrategy, self).__init__(*args)
    self._input = self._root.select(class_name="input-block-level")

  def get_gcas_from_inline(self):
    """Gets value of inline GCA field."""
    return self._input.value

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    return self._input.value

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    self._input.select(value)

  def _fill_input_field(self, value):
    """Fills input field."""
    self._input.select(value)


class PersonCAActionsStrategy(CAActionsStrategy):
  """Actions for person CA."""

  def __init__(self, *args):
    super(PersonCAActionsStrategy, self).__init__(*args)
    self._input = self._root.text_field(data_lookup="Person")
    self._chosen_person_el = self._root.element(
        class_name="person-name")

  def get_gcas_from_inline(self):
    """Gets value of inline GCA field."""
    if self._chosen_person_el.exists:
      return self._chosen_person_el.text
    return None

  def get_lcas_from_inline(self):
    """Gets value of inline LCA field."""
    if self._input.exists:  # editable
      return self._input.text
    elif self._chosen_person_el.exists:  # readonly
      return self._chosen_person_el.text
    return None

  def set_lcas_from_inline(self, value):
    """Sets value of inline LCA field."""
    self._select_user(value)

  def _fill_input_field(self, value):
    """Fills input field."""
    self._select_user(value)

  def _select_user(self, value):
    """Chooses user."""
    self._input.send_keys(value)
    ui_utils.select_user(self._root, value)
