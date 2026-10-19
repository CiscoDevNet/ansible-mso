#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg_intra_esg_contract
short_description: Manage ESG intra-ESG contracts in schema templates
description:
- Manage Endpoint Security Group (ESG) intra-ESG contract associations in Application Profiles (ANPs) in schema templates on Cisco ACI Multi-Site.
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
    - The name of the ESG that contains the intra-ESG contract association.
    type: str
    required: true
  contract:
    description:
    - The contract to associate with the ESG for intra-ESG communication.
    - The normalized contract reference uniquely identifies the association.
    - Required when O(state) is C(present) or C(absent).
    - This argument is not required when querying all intra-ESG contracts on the ESG.
    type: dict
    suboptions:
      name:
        description:
        - The name of the referenced contract.
        type: str
        required: true
      schema:
        description:
        - The schema that defines the referenced contract.
        - If unspecified, this defaults to the current O(schema).
        type: str
      template:
        description:
        - The template that defines the referenced contract.
        - If unspecified, this defaults to the current O(template).
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an intra-ESG contract association or all intra-ESG contracts on the ESG.
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
- The referenced O(contract) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_contract_filter) to create the contract with a filter.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_esg
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Associate a contract in the current schema and template with an ESG
  cisco.mso.mso_schema_template_anp_esg_intra_esg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    contract:
      name: Contract 1
    state: present

- name: Query a specific ESG intra-ESG contract association
  cisco.mso.mso_schema_template_anp_esg_intra_esg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    contract:
      name: Contract 1
      schema: Schema 1
      template: Template 1
    state: query
  register: query_result

- name: Query all intra-ESG contracts on an ESG
  cisco.mso.mso_schema_template_anp_esg_intra_esg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Remove an ESG intra-ESG contract association
  cisco.mso.mso_schema_template_anp_esg_intra_esg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    contract:
      name: Contract 1
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        esg=dict(type="str", required=True),
        contract=dict(type="dict", options=mso_reference_spec()),  # This parameter is not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract"]],
            ["state", "present", ["contract"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    contract = module.params.get("contract")
    if contract is not None and contract.get("template") is not None:
        contract["template"] = contract["template"].replace(" ", "")
    state = module.params.get("state")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_esg(esg)
    contract_ref = mso.make_reference(contract, "contract", mso_schema.id, template)

    if state == "query":
        if contract is None:
            mso.existing = mso_schema.schema_objects["template_anp_esg"].details.get("intraEsgContracts") or []
        else:
            mso_schema.set_template_anp_esg_intra_esg_contract(contract_ref)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg_intra_esg_contract").details
        mso.exit_json()

    mso_schema.set_template_anp_esg_intra_esg_contract(contract_ref, fail_module=False)
    intra_esg_contract = mso_schema.schema_objects.get("template_anp_esg_intra_esg_contract")
    mso.previous = mso.existing = intra_esg_contract.details if intra_esg_contract else mso.existing

    intra_esg_contracts_path = "/templates/{0}/anps/{1}/esgs/{2}/intraEsgContracts".format(template, anp, esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(intra_esg_contracts_path, intra_esg_contract.index)))

    elif state == "present":
        payload = dict(contractRef=contract_ref)

        mso.sanitize(payload, collate=True)

        if not mso.existing:
            ops.append(dict(op="add", path="{0}/-".format(intra_esg_contracts_path), value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
