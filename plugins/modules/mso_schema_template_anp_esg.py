#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg
short_description: Manage Endpoint Security Groups (ESGs) in schema templates
description:
- Manage Endpoint Security Groups (ESGs) in Application Profiles (ANPs) in schema templates on Cisco ACI Multi-Site.
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
    - The name of the ESG to manage.
    - This argument is not required when querying all ESGs in an ANP.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  description:
    description:
    - The ESG description.
    type: str
  intra_esg:
    description:
    - Whether intra-ESG communication is enforced.
    type: str
    choices: [ enforced, unenforced ]
  shutdown:
    description:
    - Administratively disable the ESG.
    - C(true) maps to the API value C(adminShut), and C(false) maps to C(adminUp).
    type: bool
  preferred_group:
    description:
    - Whether to include the ESG in the preferred group.
    type: bool
  vrf:
    description:
    - The VRF associated with the ESG.
    - Required when creating an ESG. If omitted when updating an existing ESG, its current VRF association is retained.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF.
        type: str
        required: true
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If unspecified, the current schema is used.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        - If unspecified, the current template is used.
        type: str
  deployment_immediacy:
    description:
    - The deployment immediacy configured for the ESG.
    type: str
    choices: [ immediate, lazy ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The O(schema) and O(template) must exist before using this module.
  Use M(cisco.mso.mso_schema_template) to create the schema and template.
- The O(anp) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_anp) to create the ANP.
- O(vrf) is required when creating an ESG, and the referenced VRF must exist.
  When updating an ESG, O(vrf) can be omitted to retain the current VRF association.
  Use M(cisco.mso.mso_schema_template_vrf) to create the VRF.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an ESG
  cisco.mso.mso_schema_template_anp_esg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    display_name: ESG 1
    description: Application security group
    intra_esg: unenforced
    shutdown: false
    preferred_group: false
    vrf:
      name: VRF 1
    deployment_immediacy: lazy
    state: present

- name: Update the ESG and administratively shut it down
  cisco.mso.mso_schema_template_anp_esg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    shutdown: true
    state: present

- name: Query an ESG
  cisco.mso.mso_schema_template_anp_esg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Query all ESGs in an ANP
  cisco.mso.mso_schema_template_anp_esg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    state: query
  register: query_result

- name: Remove an ESG
  cisco.mso.mso_schema_template_anp_esg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
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
        esg=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        display_name=dict(type="str"),
        description=dict(type="str"),
        intra_esg=dict(type="str", choices=["enforced", "unenforced"]),
        shutdown=dict(type="bool"),
        preferred_group=dict(type="bool"),
        vrf=dict(type="dict", options=mso_reference_spec()),
        deployment_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["esg"]],
            ["state", "present", ["esg"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    display_name = module.params.get("display_name")
    description = module.params.get("description")
    intra_esg = module.params.get("intra_esg")
    shutdown = module.params.get("shutdown")
    preferred_group = module.params.get("preferred_group")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf["template"].replace(" ", "")
    deployment_immediacy = module.params.get("deployment_immediacy")
    state = module.params.get("state")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    # This operational value can change independently of ESG configuration, so exclude it from module state.
    delete_keys = ["deploymentImmediacyOperational"]

    if state == "query":
        if esg is None:
            mso.existing = mso_schema.schema_objects["template_anp"].details.get("esgs") or []
            for item in mso.existing:
                mso.recursive_dict_from_ref(item)
                mso.delete_keys_from_dict(item, delete_keys)
        else:
            mso_schema.set_template_anp_esg(esg)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg").details
            mso.delete_keys_from_dict(mso.existing, delete_keys)
        mso.exit_json()

    mso_schema.set_template_anp_esg(esg, fail_module=False)
    template_anp_esg = mso_schema.schema_objects.get("template_anp_esg")
    if template_anp_esg:
        mso.delete_keys_from_dict(template_anp_esg.details, delete_keys)
    mso.previous = mso.existing = template_anp_esg.details if template_anp_esg else mso.existing

    esgs_path = "/templates/{0}/anps/{1}/esgs".format(template, anp)
    esg_path = "{0}/{1}".format(esgs_path, template_anp_esg.details.get("name") if template_anp_esg else esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=esg_path))

    elif state == "present":
        payload = dict(
            name=esg,
            displayName=display_name if display_name is not None else (esg if not mso.existing else None),
            description=description,
            intraEsg=intra_esg,
            shutdown=None if shutdown is None else ("adminShut" if shutdown else "adminUp"),
            preferredGroup=preferred_group,
            vrfRef=mso.make_reference(vrf, "vrf", mso_schema.id, template),
            deploymentImmediacy=deployment_immediacy,
            epgType="security",
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, esg_path, payload)
        else:
            ops.append(dict(op="add", path=esgs_path + "/-", value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
