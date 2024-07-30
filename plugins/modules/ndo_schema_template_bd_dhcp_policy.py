#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_schema_template_bd_dhcp_policy
short_description: Manage BD DHCP Policies in schema templates
description:
- Manage BD DHCP policies in schema templates on Cisco ACI Multi-Site.
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
    - The name of the template to change.
    type: str
    required: true
  bd:
    description:
    - The name of the BD to manage.
    type: str
    required: true
  dhcp_relay_policy:
    description:
    - The name of the DHCP Relay Policy.
    type: str
  dhcp_relay_policy_template:
    description:
    - The tenant template name in which the DHCP Relay Policy resides.
    - This parameter is required when the O(dhcp_relay_policy) is provided.
    type: str
  dhcp_option_policy:
    description:
    - The name of the DHCP Option Policy.
    - When the O(dhcp_option_policy) is provided, the O(dhcp_relay_policy) must also be provided.
    type: str
  dhcp_option_policy_template:
    description:
    - The tenant template name in which the DHCP Option Policy resides.
    - This parameter will use the O(dhcp_relay_policy_template) when not provided.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- This module can only be used on versions of MSO that are 4.x or greater.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new DHCP policy to a BD
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    dhcp_relay_policy_template: ansible_tenant_template
    dhcp_option_policy: ansible_test_option
    state: present

- name: Query a specific BD DHCP Policy
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    dhcp_relay_policy_template: ansible_tenant_template
    state: query
  register: query_result

- name: Query all BD DHCP Policies
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    state: query
  register: query_result

- name: Remove a DHCP policy from a BD
  cisco.mso.ndo_schema_template_bd_dhcp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    bd: BD1
    dhcp_relay_policy: ansible_test_relay
    dhcp_relay_policy_template: ansible_tenant_template
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair

# Template cache is created to limit the amount of API calls for ref to name translations
TEMPLATE_CACHE = {}


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", required=True),
        dhcp_relay_policy=dict(type="str"),
        dhcp_relay_policy_template=dict(type="str"),
        dhcp_option_policy=dict(type="str"),
        dhcp_option_policy_template=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["dhcp_relay_policy"]],
            ["state", "present", ["dhcp_relay_policy"]],
        ],
        required_together=[
            ["dhcp_relay_policy", "dhcp_relay_policy_template"],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    dhcp_relay_policy = module.params.get("dhcp_relay_policy")
    dhcp_relay_policy_template = module.params.get("dhcp_relay_policy_template")
    dhcp_option_policy = module.params.get("dhcp_option_policy")
    dhcp_option_policy_template = module.params.get("dhcp_option_policy_template")
    state = module.params.get("state")

    dhcp_labels_path = "/templates/{0}/bds/{1}/dhcpLabels".format(template, bd)

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template_bd(bd)

    templates = []
    tenant_id = mso_schema.schema_objects["template"].details.get("tenantId")

    if dhcp_relay_policy:
        dhcp_option_label_ref = ""
        dhcp_option_label_name = ""
        existing_dhcp_relay_policy = {}

        dhcp_relay_policy_match = get_dhcp_relay_policy_match_from_template(dhcp_relay_policy_template, mso, "name", dhcp_relay_policy, fail_module=True)
        mso_schema.set_template_bd_dhcp_relay_policy(dhcp_relay_policy_match.details.get("uuid"), False)
        if mso_schema.schema_objects.get("template_bd_dhcp_relay_policy") is not None:
            dhcp_labels_path = "{0}/{1}".format(dhcp_labels_path, mso_schema.schema_objects["template_bd_dhcp_relay_policy"].index)
            mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details["name"] = dhcp_relay_policy

            dhcp_option_label_ref = mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details.get("dhcpOptionLabel", {}).get("ref")
            if dhcp_option_label_ref:
                templates = [template for template in [dhcp_relay_policy_template, dhcp_option_policy_template] if template]
                dhcp_option_label_name = get_dhcp_option_label(mso, dhcp_option_label_ref, templates, tenant_id).details.get("name")
                mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details["dhcpOptionLabel"]["name"] = dhcp_option_label_name

            existing_dhcp_relay_policy = mso_schema.schema_objects["template_bd_dhcp_relay_policy"].details
    else:
        existing_dhcp_relay_policy = mso_schema.schema_objects["template_bd"].details.get("dhcpLabels", [])
        for dhcp_relay_policy in existing_dhcp_relay_policy:
            dhcp_relay_policy["name"] = get_dhcp_relay_label(mso, dhcp_relay_policy.get("ref"), tenant_id).details.get("name")
            dhcp_option_label_ref = dhcp_relay_policy.get("dhcpOptionLabel", {}).get("ref")
            if dhcp_option_label_ref:
                option = get_dhcp_option_label(mso, dhcp_option_label_ref, templates, tenant_id)
                if option:
                    dhcp_relay_policy["dhcpOptionLabel"]["name"] = option.details.get("name")

    if state == "query":
        mso.existing = existing_dhcp_relay_policy
        mso.exit_json()

    ops = []
    mso.previous = existing_dhcp_relay_policy

    if state == "absent":
        if existing_dhcp_relay_policy:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=dhcp_labels_path))

    if state == "present":

        payload = dict(ref=dhcp_relay_policy_match.details.get("uuid"), name=dhcp_relay_policy)

        if dhcp_option_policy:

            if dhcp_option_label_name == dhcp_option_policy:
                payload.update(dhcpOptionLabel=dict(ref=dhcp_option_label_ref, name=dhcp_option_policy))
            else:
                if (not dhcp_option_policy_template or dhcp_option_policy_template == dhcp_relay_policy_template) and TEMPLATE_CACHE.get(
                    dhcp_relay_policy_template
                ):
                    TEMPLATE_CACHE[dhcp_option_policy_template] = TEMPLATE_CACHE[dhcp_relay_policy_template]

                dhcp_option_policy_match = get_dhcp_option_policy_match_from_template(dhcp_option_policy_template, mso, "name", dhcp_option_policy, True)

                payload.update(dhcpOptionLabel=dict(ref=dhcp_option_policy_match.details.get("uuid"), name=dhcp_option_policy))

        mso.sanitize(payload, collate=True)

        if existing_dhcp_relay_policy:
            ops.append(dict(op="replace", path=dhcp_labels_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path="{0}/{1}".format(dhcp_labels_path, "-"), value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


def get_dhcp_option_label(mso, dhcp_option_label_ref, templates, tenant_id):
    # Check if the DHCP Option Label exists in the provided templates since they are most likely to be used
    for template_name in templates:
        match = get_dhcp_option_policy_match_from_template(template_name, mso, "uuid", dhcp_option_label_ref)
        if match:
            return match

    # Check all other existing tenant templates for the DHCP Option Label Name when not found in the provided templates
    tenant_templates = MSOTemplate(mso, "tenant")
    for template in tenant_templates.template:
        # Check only tenant templates that belong to the same tenant as the BD
        if template.get("templateName") in templates or template.get("tenantId") != tenant_id:
            continue
        match = get_dhcp_option_policy_match_from_template(template.get("templateName"), mso, "uuid", dhcp_option_label_ref)
        if match:
            return match


def get_dhcp_option_policy_match_from_template(template_name, mso, key, dhcp_option_label, fail_module=False):
    kv_list = [KVPair(key, dhcp_option_label)]
    template = TEMPLATE_CACHE.get(template_name)
    if not template:
        template = MSOTemplate(mso, "tenant", template_name)
        TEMPLATE_CACHE[template_name] = template
    existing_dhcp_option_policies = template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("dhcpOptionPolicies", [])
    return template.get_object_by_key_value_pairs("DHCP Option Policy", existing_dhcp_option_policies, kv_list, fail_module)


def get_dhcp_relay_label(mso, dhcp_relay_label_ref, tenant_id):
    # Check all other existing tenant templates for the DHCP Relay Label Name when not found in the provided templates
    tenant_templates = MSOTemplate(mso, "tenant")
    for template in tenant_templates.template:
        # Check only tenant templates that belong to the same tenant as the BD
        if template.get("tenantId") != tenant_id:
            continue
        match = get_dhcp_relay_policy_match_from_template(template.get("templateName"), mso, "uuid", dhcp_relay_label_ref)
        if match:
            return match


def get_dhcp_relay_policy_match_from_template(template_name, mso, key, dhcp_relay_label, fail_module=False):
    kv_list = [KVPair(key, dhcp_relay_label)]
    template = TEMPLATE_CACHE.get(template_name)
    if not template:
        template = MSOTemplate(mso, "tenant", template_name)
        TEMPLATE_CACHE[template_name] = template
    existing_dhcp_relay_policies = template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("dhcpRelayPolicies", [])
    return template.get_object_by_key_value_pairs("DHCP Relay Policy", existing_dhcp_relay_policies, kv_list, fail_module)


if __name__ == "__main__":
    main()
