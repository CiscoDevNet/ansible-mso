#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_endpoint_ip_tag_policy
short_description: Manage Endpoint IP Tag Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Endpoint IP Tag Policies on Cisco Nexus Dashboard Orchestrator (NDO).
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
  endpoint_ip_address:
    description:
    - The endpoint IP address of the Endpoint IP Tag Policy.
    type: str
    aliases: [ ip ]
  uuid:
    description:
    - The UUID of the Endpoint IP Tag Policy.
    - The UUID must be used when updating O(endpoint_ip_address) or O(vrf).
    type: str
    aliases: [ enpoint_ip_tag_policy_uuid ]
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
- The O(vrf) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_vrf) to create the VRF.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment:
- cisco.mso.modules
- cisco.mso.vrf_references
- cisco.mso.annotations_and_tags
"""

EXAMPLES = r"""
- name: Create an Endpoint IP Tag Policy
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_ip_address: 1.1.1.1
    vrf:
      reference:
        name: ansible_vrf
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
  register: create_enpoint_ip_tag_policy

- name: Update an Endpoint IP Tag Policy using IP address and VRF
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_ip_address: 1.1.1.1
    vrf:
      reference:
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

- name: Update an Endpoint IP Tag Policy using UUID
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    uuid: "{{ create_enpoint_ip_tag_policy.current.uuid }}"
    endpoint_ip_address: 2.2.2.2
    vrf:
      reference:
        name: ansible_vrf_2
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

- name: Query an Endpoint IP Tag Policy using IP address and VRF
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_ip_address: 2.2.2.2
    vrf:
      reference:
        name: ansible_vrf
        template: ansible_tenant_template
        schema: ansible_schema
    state: query
  register: query_with_ip_and_vrf

- name: Query an Endpoint IP Tag Policy using UUID
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_enpoint_ip_tag_policy.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Endpoint IP Tag Policies in a template
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    state: query
  register: query_all_objects

- name: Delete an Endpoint IP Tag Policy using its IP address and VRF
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    endpoint_ip_address: 1.1.1.1
    vrf:
      reference:
        name: ansible_vrf
        template: ansible_tenant_template
        schema: ansible_schema
    state: absent

- name: Delete an Endpoint IP Tag Policy using UUID
  cisco.mso.ndo_endpoint_ip_tag_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy_template
    uuid: "{{ create_enpoint_ip_tag_policy.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    ndo_schema_template_object_references_spec,
    ndo_tags_annotations_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        endpoint_ip_address=dict(type="str", aliases=["ip"]),
        uuid=dict(type="str", aliases=["enpoint_ip_tag_policy_uuid"]),
        vrf=ndo_schema_template_object_references_spec(),
        annotations=ndo_tags_annotations_spec(),
        policy_tags=ndo_tags_annotations_spec(aliases=["tags"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
        ],
        required_if=[
            ["state", "absent", ["endpoint_ip_address", "uuid"], True],
            ["state", "present", ["endpoint_ip_address", "uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    ip = module.params.get("endpoint_ip_address")
    uuid = module.params.get("uuid")
    vrf = module.params.get("vrf")
    annotations = module.params.get("annotations")
    policy_tags = module.params.get("policy_tags")
    state = module.params.get("state")
    reference_dict = {
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

    if ip and not uuid and not vrf:
        mso.fail_json(msg="when providing an IP address without UUID, one of the following is required: vrf")

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    tenant_id = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("tenantId")
    templates_objects_path = "templates/objects"
    if vrf:
        if vrf.get("uuid"):
            vrf_uuid = vrf["uuid"]
        elif vrf.get("reference"):
            vrf_object = mso_template.get_vrf_object(vrf["reference"], tenant_id, templates_objects_path)
            vrf_uuid = vrf_object.details.get("uuid")

    match = mso_template.get_endpoint_ip_tag_policy_object(uuid, ip, vrf_uuid)

    if (uuid or (ip and vrf_uuid)) and match:
        mso.existing = mso.previous = copy.deepcopy(
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
        )  # Query a specific object
    elif match:
        mso.existing = [mso_template.update_config_with_template_and_references(obj, reference_dict) for obj in match]  # Query all objects

    enpoint_ip_tag_policy_path = "/tenantPolicyTemplate/template/endpointIPTagPolicies/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":

        mso_values = {
            "ip": ip,
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
            append_update_ops_data(ops, match.details, enpoint_ip_tag_policy_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=enpoint_ip_tag_policy_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=enpoint_ip_tag_policy_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_endpoint_ip_tag_policy_object(uuid, ip, vrf_uuid, search_object=response)
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
