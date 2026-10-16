#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg_tag_selector
short_description: Manage ESG tag selectors in schema templates
description:
- Manage Endpoint Security Group (ESG) tag selectors in Application Profiles (ANPs) in schema templates on Cisco ACI Multi-Site.
- This module is only supported on ND v4.1 (NDO v5.1) and later.
author:
- Akini Ross (@akinross)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  anp:
    description:
    - The ANP that contains the ESG.
    type: str
    required: true
  esg:
    description:
    - The name of the ESG that contains the tag selector.
    type: str
    required: true
  tag_key:
    description:
    - The tag key matched by the selector.
    - Together with O(operator) and O(tag_value), identifies the tag selector.
    - Required when O(state) is C(present) or C(absent), or when querying a specific tag selector.
    - Omit O(tag_key), O(operator) and O(tag_value) to query all tag selectors on the ESG.
    type: str
    aliases: [ key ]
  operator:
    description:
    - The comparison operator used to match the tag value.
    - Required when O(state) is C(present) or C(absent), or when querying a specific tag selector.
    type: str
    choices: [ equals, contains, regex ]
  tag_value:
    description:
    - The tag value matched by the selector.
    - Required when O(state) is C(present) or C(absent), or when querying a specific tag selector.
    type: str
    aliases: [ value ]
  description:
    description:
    - The description of the tag selector.
    - This is the only mutable attribute of an existing tag selector.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing a tag selector or all tag selectors on the ESG.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The O(schema) and O(template) must exist before using this module.
  Use M(cisco.mso.mso_schema_template) to create the schema and template.
- The O(anp) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_anp) to create the ANP.
- The O(esg) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_anp_esg) to create the ESG.
- Tag selectors are identified by the full combination of O(tag_key), O(operator) and O(tag_value).
  Multiple selectors can use the same key with different operators or values.
  Changing any identity argument selects a different resource; remove the old selector separately if needed.
- When O(state) is C(query), provide either all three identity arguments or none of them.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_esg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an ESG tag selector
  cisco.mso.mso_schema_template_anp_esg_tag_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    tag_key: __vmm::vmname
    operator: contains
    tag_value: web
    state: present

- name: Update an ESG tag selector description
  cisco.mso.mso_schema_template_anp_esg_tag_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    tag_key: __vmm::vmname
    operator: contains
    tag_value: web
    description: Select web virtual machines
    state: present

- name: Query a specific ESG tag selector
  cisco.mso.mso_schema_template_anp_esg_tag_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    tag_key: __vmm::vmname
    operator: contains
    tag_value: web
    state: query
  register: query_result

- name: Query all tag selectors on an ESG
  cisco.mso.mso_schema_template_anp_esg_tag_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Remove an ESG tag selector
  cisco.mso.mso_schema_template_anp_esg_tag_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    tag_key: __vmm::vmname
    operator: contains
    tag_value: web
    state: absent
"""

RETURN = r"""
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        esg=dict(type="str", required=True),
        tag_key=dict(type="str", aliases=["key"], no_log=False),  # This parameter is not required for querying all objects
        operator=dict(type="str", choices=["equals", "contains", "regex"]),
        tag_value=dict(type="str", aliases=["value"]),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tag_key", "operator", "tag_value"]],
            ["state", "present", ["tag_key", "operator", "tag_value"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    tag_key = module.params.get("tag_key")
    operator = module.params.get("operator")
    tag_value = module.params.get("tag_value")
    description = module.params.get("description")
    state = module.params.get("state")

    identity = (tag_key, operator, tag_value)
    if state == "query" and any(value is not None for value in identity) and any(value is None for value in identity):
        module.fail_json(msg="tag_key, operator and tag_value must be provided together when state is query")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_esg(esg)

    if state == "query":
        if tag_key is None:
            mso.existing = mso_schema.schema_objects["template_anp_esg"].details.get("tagSelectors") or []
        else:
            mso_schema.set_template_anp_esg_tag_selector(tag_key, operator, tag_value)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg_tag_selector").details
        mso.exit_json()

    mso_schema.set_template_anp_esg_tag_selector(tag_key, operator, tag_value, fail_module=False)
    tag_selector = mso_schema.schema_objects.get("template_anp_esg_tag_selector")
    mso.previous = mso.existing = tag_selector.details if tag_selector else mso.existing

    tag_selectors_path = "/templates/{0}/anps/{1}/esgs/{2}/tagSelectors".format(template, anp, esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(tag_selectors_path, tag_selector.index)))

    elif state == "present":
        payload = dict(key=tag_key, operator=operator, value=tag_value, description=description)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, "{0}/{1}".format(tag_selectors_path, tag_selector.index), payload)
        else:
            ops.append(dict(op="add", path="{0}/-".format(tag_selectors_path), value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
