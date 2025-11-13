#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_endpoint_mac_tag_policy
short_description: Manage Endpoint MAC Tag Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Endpoint MAC Tag Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v4.1 (NDO v5.1) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Tenant Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Tenant Policy template.
    - This parameter or O(template) is required.
    type: str
  endpoint_mac_address:
    description:
    - The endpoint MAC address of the Endpoint MAC Tag Policy.
    type: str
    aliases: [ mac ]
  uuid:
    description:
    - The UUID of the Endpoint MAC Tag Policy.
    - The UUID must be used when updating O(endpoint_mac_address), O(bridge_domain) or O(vrf).
    type: str
    aliases: [ endpoint_mac_tag_policy_uuid ]
  bridge_domain:
    description:
    - The Bridge Domain associated with the Endpoint MAC Tag Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Bridge Domain.
        required: true
        type: str
      schema:
        description:
        - The schema associated with the Bridge Domain.
        required: true
        type: str
      template:
        description:
        - The template associated with the Bridge Domain.
        required: true
        type: str
    aliases: [ bd ]
  bridge_domain_uuid:
    description:
    - The UUID of the Bridge Domain associated with the Endpoint MAC Tag Policy.
    type: str
    aliases: [ bd_uuid ]
  vrf:
    description:
    - The VRF associated with the Endpoint MAC Tag Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF.
        required: true
        type: str
      schema:
        description:
        - The schema associated with the VRF.
        required: true
        type: str
      template:
        description:
        - The template ID associated with the VRF.
        required: true
        type: str
  vrf_uuid:
    description:
    - The UUID of the VRF associated with the Endpoint MAC Tag Policy.
    type: str
  annotations:
    description:
    - The list of annotations of the Endpoint MAC Tag Policy.
    - Providing an empty list will remove the O(annotations) from the Endpoint MAC Tag Policy.
    type: list
    elements: dict
    suboptions:
      key:
        description:
        - The annotation key.
        type: str
      value:
        description:
        - The  value associated with O(annotations.key).
        type: str
  policy_tags:
    description:
    - The list of Policy Tags of the Endpoint MAC Tag Policy.
    - Providing an empty list will remove the O(policy_tags) from the Endpoint MAC Tag Policy.
    type: list
    elements: dict
    suboptions:
      key:
        description:
        - The Policy Tag key.
        type: str
      value:
        description:
        - The value associated with O(policy_tags.key).
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant Policy template.
- The O(bridge_domain) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_bd) to create the Bridge Domain.
- The O(vrf) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_vrf) to create the VRF.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.mso_schema_template_bd
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an Endpoint MAC Tag Policy
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 01:23:45:67:89:AB
    bridge_domain:
      name: ansible_bd
      template: ansible_tenant_template
      schema: ansible_schema
    annotations:
      - key: key_1
        value: value_1
      - key: key_2
        value: value_2
    policy_tags:
      - key: key_1
        value: value_1
      - key: key_2
        value: value_2
    state: present
  register: create_endpoint_mac_tag_policy

- name: Update an Endpoint MAC Tag Policy using MAC address and Bridge Domain
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 01:23:45:67:89:AB
    bridge_domain:
      name: ansible_bd
      template: ansible_tenant_template
      schema: ansible_schema
    annotations:
      - key: key_1
        value: value_1
    policy_tags:
      - key: key_1
        value: value_1
      - key: key_2
        value: value_2
      - key: key_3
        value: value_3
    state: present

- name: Update an Endpoint MAC Tag Policy using UUID
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    uuid: "{{ create_endpoint_mac_tag_policy.current.uuid }}"
    endpoint_mac_address: 2C:54:91:88:C9:E3
    vrf:
      name: ansible_vrf
      template: ansible_tenant_template
      schema: ansible_schema
    annotations:
      - key: key_1
        value: value_1
    policy_tags:
      - key: key_1
        value: value_1
      - key: key_2
        value: value_2
      - key: key_3
        value: value_3
    state: present

- name: Query an Endpoint MAC Tag Policy using MAC address and Bridge Domain
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 01:23:45:67:89:AB
    bridge_domain:
      name: ansible_bd
      template: ansible_tenant_template
      schema: ansible_schema
    state: query
  register: query_with_mac_and_bd

- name: Query an Endpoint MAC Tag Policy using MAC address and VRF
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 2C:54:91:88:C9:E3
    vrf:
      name: ansible_vrf
      template: ansible_tenant_template
      schema: ansible_schema
    state: query
  register: query_with_mac_and_vrf

- name: Query an Endpoint MAC Tag Policy using UUID
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_endpoint_mac_tag_policy.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Endpoint MAC Tag Policies in a template
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    state: query
  register: query_all_objects

- name: Delete an Endpoint MAC Tag Policy using its MAC address and Bridge Domain
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 01:23:45:67:89:AB
    bridge_domain:
      name: ansible_bd
      template: ansible_tenant_template
      schema: ansible_schema
    state: absent

- name: Delete an Endpoint MAC Tag Policy using its MAC address and VRF
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_mac_address: 01:23:45:67:89:AB
    vrf:
      name: ansible_vrf
      template: ansible_tenant_template
      schema: ansible_schema
    state: absent

- name: Delete an Endpoint MAC Tag Policy using UUID
  cisco.mso.ndo_endpoint_mac_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    uuid: "{{ create_endpoint_mac_tag_policy.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        endpoint_mac_address=dict(type="str", aliases=["mac"]),
        uuid=dict(type="str", aliases=["endpoint_mac_tag_policy_uuid"]),
        bridge_domain=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                schema=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
            aliases=["bd"],
        ),
        bridge_domain_uuid=dict(type="str", aliases=["bd_uuid"]),
        vrf=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                schema=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
        ),
        vrf_uuid=dict(type="str"),
        annotations=dict(
            type="list",
            elements="dict",
            options=dict(
                key=dict(type="str", no_log=False),
                value=dict(type="str"),
            ),
        ),
        policy_tags=dict(
            type="list",
            elements="dict",
            options=dict(
                key=dict(type="str", no_log=False),
                value=dict(type="str"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("bridge_domain", "bridge_domain_uuid"),
            ("vrf", "vrf_uuid"),
            ("bridge_domain", "vrf"),
            ("bridge_domain_uuid", "vrf_uuid"),
            ("bridge_domain", "vrf_uuid"),
            ("bridge_domain_uuid", "vrf"),
        ],
        required_if=[
            ["state", "absent", ["endpoint_mac_address", "uuid"], True],
            ["state", "present", ["endpoint_mac_address", "uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    mac = module.params.get("endpoint_mac_address")
    uuid = module.params.get("uuid")
    bd = module.params.get("bridge_domain")
    bd_uuid = module.params.get("bridge_domain_uuid")
    vrf = module.params.get("vrf")
    vrf_uuid = module.params.get("vrf_uuid")
    annotations = module.params.get("annotations")
    policy_tags = module.params.get("policy_tags")
    state = module.params.get("state")
    reference_dict = {
        "bd": {
            "name": "bdName",
            "reference": "bdRef",
            "type": "bd",
            "template": "bdTemplateName",
            "templateId": "bdTemplateId",
            "schema": "bdSchemaName",
            "schemaId": "bdSchemaId",
        },
        "vrf": {
            "name": "vrfName",
            "reference": "vrfRef",
            "type": "vrf",
            "template": "vrfTemplateName",
            "templateId": "vrfTemplateId",
            "schema": "vrfSchemaName",
            "schemaId": "vrfSchemaId",
        },
    }

    if mac and not uuid and not (bd or vrf or vrf_uuid or bd_uuid):
        mso.fail_json(msg="when providing a MAC address without UUID, one of the following is required: bridge_domain, bridge_domain_uuid, vrf, vrf_uuid")

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    tenant_id = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("tenantId")
    templates_objects_path = "templates/objects"
    if vrf and not vrf_uuid:
        vrf_object = mso_template.get_vrf_object(vrf, tenant_id, templates_objects_path)
        vrf_uuid = vrf_object.details.get("uuid")
    elif bd and not bd_uuid:
        bd_object = mso_template.get_bd_object(bd, tenant_id, templates_objects_path)
        bd_uuid = bd_object.details.get("uuid")

    match = mso_template.get_endpoint_mac_tag_policy_object(uuid, mac, bd_uuid, vrf_uuid)

    if (uuid or (mac and (bd_uuid or vrf_uuid))) and match:
        mso.existing = mso.previous = copy.deepcopy(
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
        )  # Query a specific object
    elif match:
        mso.existing = [mso_template.update_config_with_template_and_references(obj, reference_dict) for obj in match]  # Query all objects

    endpoint_mac_tag_policy_path = "/tenantPolicyTemplate/template/endpointMacTagPolicies/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":

        mso_values = {
            "mac": mac,
            "bdRef": bd_uuid,
            "vrfRef": vrf_uuid,
        }

        if annotations:
            mso_values["tagAnnotations"] = [
                {
                    "tagKey": annotation.get("key"),
                    "tagValue": annotation.get("value"),
                }
                for annotation in annotations
            ]
        if policy_tags:
            mso_values["policyTags"] = policy_tags

        if match:
            remove_data = []
            if annotations == []:
                remove_data.append("tagAnnotations")
            if policy_tags == []:
                remove_data.append("policyTags")
            if bd_uuid and match.details.get("vrfRef"):
                remove_data.append("vrfRef")
            elif match.details.get("bdRef") and vrf_uuid:
                remove_data.append("bdRef")
            append_update_ops_data(ops, match.details, endpoint_mac_tag_policy_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=endpoint_mac_tag_policy_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=endpoint_mac_tag_policy_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_endpoint_mac_tag_policy_object(uuid, mac, bd_uuid, vrf_uuid, search_object=response)
        if match:
            mso.existing = mso_template.update_config_with_template_and_references(match.details, reference_dict)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if mso.proposed:
            mso_template.update_config_with_template_and_references(mso.proposed, reference_dict)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


if __name__ == "__main__":
    main()
