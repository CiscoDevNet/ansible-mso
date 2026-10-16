#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg_subnet_selector
short_description: Manage ESG subnet selectors in schema templates
description:
- Manage Endpoint Security Group (ESG) subnet selectors in Application Profiles (ANPs) in schema templates on Cisco ACI Multi-Site.
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
    - The name of the ESG that contains the subnet selector.
    type: str
    required: true
  ip:
    description:
    - The IP address or subnet of the subnet selector.
    - This is the exact identity of the selector and is used as supplied without normalization.
    - Required when O(state) is C(present) or C(absent).
    - This argument is not required when querying all subnet selectors on the ESG.
    type: str
  description:
    description:
    - The description of the subnet selector.
    - If omitted, the existing description is preserved.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an subnet selector or all subnet selectors on the ESG.
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
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_esg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an ESG subnet selector
  cisco.mso.mso_schema_template_anp_esg_subnet_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    ip: 10.15.35.0
    state: present

- name: Update an ESG subnet selector
  cisco.mso.mso_schema_template_anp_esg_subnet_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    ip: 10.15.35.0
    description: Updated subnet selector
    state: present

- name: Query a specific ESG subnet selector
  cisco.mso.mso_schema_template_anp_esg_subnet_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    ip: 10.15.35.0
    state: query
  register: query_result

- name: Query all subnet selectors on an ESG
  cisco.mso.mso_schema_template_anp_esg_subnet_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Remove an ESG subnet selector
  cisco.mso.mso_schema_template_anp_esg_subnet_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    ip: 10.15.35.0
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
        ip=dict(type="str"),  # This parameter is not required for querying all objects
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ip"]],
            ["state", "present", ["ip"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    ip = module.params.get("ip")
    description = module.params.get("description")
    state = module.params.get("state")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_esg(esg)

    if state == "query":
        if ip is None:
            mso.existing = mso_schema.schema_objects["template_anp_esg"].details.get("ipSubnetSelectors") or []
        else:
            mso_schema.set_template_anp_esg_subnet_selector(ip)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg_subnet_selector").details
        mso.exit_json()

    mso_schema.set_template_anp_esg_subnet_selector(ip, fail_module=False)
    subnet_selector = mso_schema.schema_objects.get("template_anp_esg_subnet_selector")
    mso.previous = mso.existing = subnet_selector.details if subnet_selector else mso.existing

    subnet_selectors_path = "/templates/{0}/anps/{1}/esgs/{2}/ipSubnetSelectors".format(template, anp, esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(subnet_selectors_path, subnet_selector.index)))

    elif state == "present":
        payload = dict(ip=ip, description=description)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, "{0}/{1}".format(subnet_selectors_path, subnet_selector.index), payload)
        else:
            ops.append(dict(op="add", path="{0}/-".format(subnet_selectors_path), value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
