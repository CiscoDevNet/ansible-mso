#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_bd_dhcp_policy
short_description: Manage BD DHCP Policy in schema templates
description:
- Manage BD DHCP policies in schema templates on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template to change.
    type: str
    required: true
  bd:
    description:
    - The name of the BD to manage.
    type: str
    required: true
  dhcp_policy:
    description:
    - The DHCP Policy
    type: str
    aliases: [ name ]
  dhcp_option_policy:
    description:
    - The DHCP Option Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the DHCP Option Policy.
        type: str
        required: true
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- This module can only be used on versions of MSO that are 3.1.1h or greater.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new DHCP policy to a BD
  cisco.mso.mso_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    name: ansible_test
    dhcp_option_policy:
      name: ansible_test_option
    state: present
  delegate_to: localhost

- name: Remove a DHCP policy from a BD
  cisco.mso.mso_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    name: ansible_test
    state: absent
  delegate_to: localhost

- name: Query a specific BD DHCP Policy
  cisco.mso.mso_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    name: ansible_test
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all BD DHCP Policies
  cisco.mso.mso_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_dhcp_option_spec, ndo_templates_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", required=True),
        dhcp_policy=dict(type="dict", options=ndo_templates_spec()),
        # dhcp_option_policy=dict(type="dict", options=mso_dhcp_option_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["dhcp_policy"]],
            ["state", "present", ["dhcp_policy"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    dhcp_policy = module.params.get("dhcp_policy")
    # dhcp_option_policy = module.params.get("dhcp_option_policy")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)
    

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get BD
    bds = [b.get("name") for b in schema_obj.get("templates")[template_idx]["bds"]]
    if bd not in bds:
        mso.fail_json(msg="Provided BD '{0}' does not exist. Existing BDs: {1}".format(bd, ", ".join(bds)))
    bd_idx = bds.index(bd)

    template_type = "tenantPolicy"

    dhcp_pol_templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    dhcp_pol_template_id = ''
    if templates:
        for temp in dhcp_pol_templates:
            if temp['templateName'] == dhcp_policy['template'] and temp['templateType'] == template_type:
                dhcp_pol_template_id = temp['templateId']

    if not dhcp_pol_template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))
        


    dhcp_pol_template = mso.request(path=f"templates/{dhcp_pol_template_id}", method="GET", api_version="v1")

    dhcp_pol_uuid = ""
    if 'template' in dhcp_pol_template['tenantPolicyTemplate'] and 'dhcpRelayPolicies' in dhcp_pol_template['tenantPolicyTemplate']['template']:
        for count, r in enumerate(dhcp_pol_template['tenantPolicyTemplate']['template']['dhcpRelayPolicies']):
            if r['name'] == dhcp_policy['name']:
                dhcp_pol_uuid = r['uuid']
    
    if not dhcp_pol_uuid:
        mso.fail_json(msg="DHCP Policy '{name}' not found".format(name=dhcp_policy['name']))
        

    # Get DHCP policies
    dhcp_policies = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["dhcpLabels"]

    for count, r in enumerate(dhcp_policies):
        if r['ref'] == dhcp_pol_uuid:
            mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["dhcpLabels"][count]
            dhcp_policy_path = "/templates/{0}/bds/{1}/dhcpLabels/{2}".format(template, bd, count)
            
        
    # if dhcp_policy['name'] in dhcp_policies:
    #     dhcp_idx = dhcp_policies.index(dhcp_policy['name'])
    #     # FIXME: Changes based on index are DANGEROUS
    #     dhcp_policy_path = "/templates/{0}/bds/{1}/dhcpLabels/{2}".format(template, bd, dhcp_idx)
    #     mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["dhcpLabels"][dhcp_idx]


    if state == "query":
        if dhcp_policy is None:
            mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]["dhcpLabels"]
        elif not mso.existing:
            mso.fail_json(msg="DHCP policy not associated with the bd")
        mso.exit_json()

    dhcp_policy_paths = "/templates/{0}/bds/{1}/dhcpLabels".format(template, bd)
    ops = []
    

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=dhcp_policy_path))

    elif state == "present":
        payload = dict(
            ref=dhcp_pol_uuid
        )

        mso.sanitize(payload, collate=True)
        
        if mso.existing:
            ops.append(dict(op="replace", path=dhcp_policy_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=dhcp_policy_paths + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)
        



    mso.exit_json()


if __name__ == "__main__":
    main()
