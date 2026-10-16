#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg_external_epg_selector
short_description: Manage ESG external EPG selectors in schema templates
description:
- Manage external Endpoint Group (EPG) selectors for an Endpoint Security Group (ESG) in an Application Profile (ANP)
  in a schema template on Cisco ACI Multi-Site.
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
    - The name of the ESG that contains the external EPG selector.
    type: str
    required: true
  external_epg:
    description:
    - The external EPG referenced by the selector.
    - The complete external EPG reference identifies the selector.
    - Required when O(state) is C(present) or C(absent).
    - This argument is not required when querying all external EPG selectors on the ESG.
    type: dict
    suboptions:
      name:
        description:
        - The name of the referenced external EPG.
        type: str
        required: true
      schema:
        description:
        - The schema that defines the referenced external EPG.
        - If unspecified, the current schema is used.
        type: str
      template:
        description:
        - The template that defines the referenced external EPG.
        - If unspecified, the current template is used.
        - Spaces are removed from the supplied template name.
        type: str
  description:
    description:
    - The description of the external EPG selector.
    - If omitted, the current description is retained when updating an existing selector.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an external EPG selector or all external EPG selectors on the ESG.
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
- The referenced external EPG must exist before using this module.
  Use M(cisco.mso.mso_schema_template_external_epg) to create the external EPG and its required VRF association.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_esg
- module: cisco.mso.mso_schema_template_external_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an ESG external EPG selector
  cisco.mso.mso_schema_template_anp_esg_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    external_epg:
      name: External EPG 1
    state: present

- name: Update an ESG external EPG selector
  cisco.mso.mso_schema_template_anp_esg_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    external_epg:
      name: External EPG 1
    description: Updated external EPG selector description
    state: present

- name: Query a specific ESG external EPG selector
  cisco.mso.mso_schema_template_anp_esg_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    external_epg:
      name: External EPG 1
    state: query
  register: query_result

- name: Query all external EPG selectors on an ESG
  cisco.mso.mso_schema_template_anp_esg_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Remove an ESG external EPG selector
  cisco.mso.mso_schema_template_anp_esg_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    external_epg:
      name: External EPG 1
    state: absent
"""

RETURN = r"""
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        esg=dict(type="str", required=True),
        external_epg=dict(type="dict", options=mso_reference_spec()),  # This parameter is not required for querying all objects
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["external_epg"]],
            ["state", "present", ["external_epg"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    external_epg = module.params.get("external_epg")
    if external_epg is not None and external_epg.get("template") is not None:
        external_epg["template"] = external_epg["template"].replace(" ", "")
    description = module.params.get("description")
    state = module.params.get("state")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_esg(esg)
    external_epg_ref = mso.make_reference(external_epg, "externalEpg", mso_schema.id, template)

    if state == "query":
        if external_epg is None:
            mso.existing = mso_schema.schema_objects["template_anp_esg"].details.get("extEpgSelectors") or []
        else:
            mso_schema.set_template_anp_esg_external_epg_selector(external_epg_ref)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg_external_epg_selector").details
        mso.exit_json()

    mso_schema.set_template_anp_esg_external_epg_selector(external_epg_ref, fail_module=False)
    selector = mso_schema.schema_objects.get("template_anp_esg_external_epg_selector")
    mso.previous = mso.existing = selector.details if selector else mso.existing

    selectors_path = "/templates/{0}/anps/{1}/esgs/{2}/extEpgSelectors".format(template, anp, esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(selectors_path, selector.index)))

    elif state == "present":
        payload = dict(extEpgRef=external_epg_ref, description=description)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, "{0}/{1}".format(selectors_path, selector.index), payload)
        else:
            ops.append(dict(op="add", path="{0}/-".format(selectors_path), value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
