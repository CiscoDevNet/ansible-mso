from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import TEMPLATE_TYPES
from ansible_collections.cisco.mso.plugins.module_utils.utils import check_if_all_elements_are_none


class MSOTemplates:
    def __init__(self, mso_module):
        self.mso = mso_module
        self.templates_by_id = {}
        self.templates_by_name = {}

    def get_template(self, template_type, template_name, template_id, refresh=False):
        if not refresh:
            if template_id in self.templates_by_id:
                return self.templates_by_id[template_id]
            elif (template_name, TEMPLATE_TYPES[template_type]["template_type"]) in self.templates_by_name:
                return self.templates_by_name[(template_name, TEMPLATE_TYPES[template_type]["template_type"])]

        new_template = MSOTemplate(self.mso, template_type, template_name, template_id)
        self.templates_by_id[new_template.template_id] = new_template
        self.templates_by_name[(new_template.template_name, new_template.template_type)] = new_template
        return new_template

    def get_object_uuid_from_template(self, template_type, object_type, uuid, obj, refresh=False):
        if uuid:
            return uuid

        is_empty = check_if_all_elements_are_none(obj.values()) if obj else True
        if not is_empty:
            name = obj.get("name")
            template = obj.get("template")
            template_id = obj.get("template_id")

            get_template = self.get_template(template_type, template, template_id, refresh)

            return get_template.get_template_policy_uuid(template_type, name, object_type)
