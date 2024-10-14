#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_physical_interface
short_description: Manage physical interface on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage physical interface on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric resource policy template.
    type: str
    required: true
  physical_interface:
    description:
    - The name of the physical interface.
    type: str
    aliases: [ name ]
  physical_interface_uuid:
    description:
    - The UUID of the physical interface.
    - This parameter is required when the O(physical_interface) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the physical interface.
    type: str
  nodes:
    description:
    - The node IDs where the physical interface policy will be deployed.
    type: list
    elements: int
  interfaces:
    description:
    - The interface names where the policy will be deployed.
    - The old O(interfaces) will be replaced with the new O(interfaces) during an update.
    type: list
    elements: str
  physical_interface_type:
    description:
    - The type of the interface policy group.
    type: str
    choices: [ physical, breakout ]
  physical_policy_uuid:
    description:
    - The UUID of the Interface Setting Policy.
    - This is only required when creating a new Port Channel Interface.
    - This parameter is required when O(physical_interface_type) is C(physical).
    - This parameter can be used instead of O(physical_policy).
    type: str
    aliases: [ policy_uuid, interface_policy_uuid , interface_policy_group_uuid, interface_setting_uuid]
  physical_policy:
    description:
    - The interface group policy required for physical Interface Setting Policy.
    - This parameter is required when O(physical_interface_type) is C(physical).
    - This parameter can be used instead of O(physical_policy_uuid).
    type: dict
    suboptions:
      name:
        description:
        - The name of the Port Channel Interface Setting Policy.
        type: str
      template:
        description:
        - The name of the template in which is referred the Port Channel Interface Policy Group.
        type: str
    aliases: [ policy, interface_policy, interface_policy_group, interface_setting ]
  breakout_mode:
    description:
    - The breakout mode enabled splitting of the ethernet ports.
    - This parameter is available only when O(physical_interface_type) is C(breakout).
    - The default value is C(4x10G).
    type: str
    choices: [ 4x10G, 4x25G, 4x100G ]
  interface_descriptions:
    description:
    - The interface settings defined in the interface settings policy will be applied to the interfaces on the nodes you provided.
    type: list
    elements: dict
    suboptions:
      interface_id:
        description:
        - The interface ID.
        type: str
      description:
        description:
        - The description of the interface.
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
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(physical_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_interface_setting) to create the Interface Setting Policy.
- The O(physical_policy_uuid) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_interface_setting) to create the Interface Setting Policy UUID.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an physical interface physical_interface_type physical
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface: ansible_test_physical_interface_physical
  description: "physical interface for Ansible Test"
  nodes: [101]
  interfaces: "1/1"
  physical_interface_type: physical
  physical_policy: ansible_test_interface_setting_policy_uuid
  state: present

- name: Create an physical interface physical_interface_type breakout
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface: ansible_test_physical_interface_breakout
  description: "breakout interface for Ansible Test"
  nodes: [101]
  interfaces: "1/1"
  physical_interface_type: breakout
  breakout_mode: 4x25G
  interface_descriptions:
    - interface_id: "1/1"
      description: "Interface description for 1/1"
  state: present

- name: Query all physical interfaces
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  state: query
  register: query_all

- name: Query a specific physical interface with name
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface: ansible_test_physical_interface_physical
  state: query
  register: query_one_name

- name: Query a specific physical interface with UUID
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface_uuid: ansible_test_physical_interface_uuid
  state: query
  register: query_one_uuid

- name: Delete an physical interface with name
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface: ansible_test_physical_interface_physical
  state: absent

- name: Delete an physical interface with UUID
  cisco.mso.ndo_physical_interface:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  physical_interface_uuid: ansible_test_physical_interface_uuid
  state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            physical_interface=dict(type="str", aliases=["name"]),
            physical_interface_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            nodes=dict(type="list", elements="int"),
            interfaces=dict(type="list", elements="str"),
            physical_interface_type=dict(type="str", choices=["physical", "breakout"]),
            physical_policy_uuid=dict(type="str", aliases=["policy_uuid", "interface_policy_uuid", "interface_policy_group_uuid", "interface_setting_uuid"]),
            physical_policy=dict(
                type="dict",
                options=dict(
                    name=dict(type="str"),
                    template=dict(type="str"),
                ),
                aliases=["policy", "interface_policy", "interface_policy_group", "interface_setting"],
            ),
            breakout_mode=dict(type="str", choices=["4x10G", "4x25G", "4x100G"]),
            interface_descriptions=dict(
                type="list",
                elements="dict",
                options=dict(
                    interface_id=dict(type="str"),
                    description=dict(type="str"),
                ),
            ),
            state=dict(type="str", default="query", choices=["absent", "query", "present"]),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["physical_interface", "physical_interface_uuid"], True],
            ["state", "absent", ["physical_interface", "physical_interface_uuid"], True],
        ],
        mutually_exclusive=[("physical_policy", "breakout_mode"), ("physical_policy", "physical_policy_uuid")],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    physical_interface = module.params.get("physical_interface")
    physical_interface_uuid = module.params.get("physical_interface_uuid")
    description = module.params.get("description")
    nodes = module.params.get("nodes")
    if nodes:
        nodes = [str(node) for node in nodes]
    interfaces = module.params.get("interfaces")
    if interfaces:
        interfaces = ",".join(interfaces)
    physical_interface_type = module.params.get("physical_interface_type")
    physical_policy_uuid = module.params.get("physical_policy_uuid")
    physical_policy = module.params.get("physical_policy")
    breakout_mode = module.params.get("breakout_mode")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")

    path = "/fabricResourceTemplate/template/interfaceProfiles"
    object_description = "Physical Interface Profile"

    existing_interface_policies = mso_template.template.get("fabricResourceTemplate", {}).get("template", {})
    if existing_interface_policies.get("interfaceProfiles") is not None:
        existing_interface_policies = existing_interface_policies.get("interfaceProfiles")
    else:
        existing_interface_policies = []

    if physical_interface or physical_interface_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_interface_policies,
            [KVPair("uuid", physical_interface_uuid) if physical_interface_uuid else KVPair("name", physical_interface)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_interface_policies

    if state == "present":

        if physical_policy and not physical_policy_uuid:  # check this part and see if this is required or use mutually_exclusive
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", physical_policy.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            physical_policy_uuid = fabric_policy_template.get_interface_policy_group_uuid(physical_policy.get("name"))

        if match:

            if physical_interface_type and match.details.get("policyGroupType") != physical_interface_type:
                mso.fail_json(msg="ERROR: Physical Interface type cannot be changed.")

            if physical_interface and match.details.get("name") != physical_interface:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=physical_interface))
                match.details["name"] = physical_interface

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if nodes and match.details.get("nodes") != nodes:
                ops.append(dict(op="replace", path="{0}/{1}/nodes".format(path, match.index), value=nodes))
                match.details["nodes"] = nodes

            if physical_policy_uuid and match.details.get("policy") != physical_policy_uuid:
                ops.append(dict(op="replace", path="{0}/{1}/policy".format(path, match.index), value=physical_policy_uuid))
                match.details["policy"] = physical_policy_uuid

            if breakout_mode and match.details.get("breakoutMode") != breakout_mode:
                ops.append(dict(op="replace", path="{0}/{1}/breakoutMode".format(path, match.index), value=breakout_mode))
                match.details["breakoutMode"] = breakout_mode

            if interfaces and interfaces != match.details.get("interfaces"):
                ops.append(dict(op="replace", path="{0}/{1}/interfaces".format(path, match.index), value=interfaces))
                match.details["interfaces"] = interfaces

            # Node changes are not reflected on UI
            if interface_descriptions and match.details.get("interfaceDescriptions") != interface_descriptions:
                updated_interface_descriptions = validate_interface_description(interface_descriptions)
                ops.append(dict(op="replace", path="{0}/{1}/interfaceDescriptions".format(path, match.index), value=updated_interface_descriptions))
                match.details["interfaceDescriptions"] = updated_interface_descriptions
            elif interface_descriptions == [] and match.details.get("interfaceDescriptions"):
                ops.append(dict(op="remove", path="{0}/{1}/interfaceDescriptions".format(path, match.index)))

            mso.sanitize(match.details)

        else:
            if not nodes:
                mso.fail_json(msg=("ERROR: Missing 'nodes' for creating a Physical Interface."))

            if not physical_interface_type:
                mso.fail_json(msg=("ERROR: Missing physical interface type for creating a Physical Interface."))

            payload = {
                "name": physical_interface,
                "templateId": mso_template.template.get("templateId"),
                "schemaId": mso_template.template.get("schemaId"),
                "nodes": nodes,
                "interfaces": interfaces,
                "policyGroupType": physical_interface_type,
            }

            if description:
                payload["description"] = description

            if physical_interface_type == "physical" and physical_policy_uuid:
                payload["policy"] = physical_policy_uuid

            if physical_interface_type == "breakout" and breakout_mode:
                payload["breakoutMode"] = breakout_mode

            if interface_descriptions:
                payload["interfaceDescriptions"] = validate_interface_description(interface_descriptions)

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        interface_policies = response.get("fabricResourceTemplate", {}).get("template", {}).get("interfaceProfiles", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            interface_policies,
            [KVPair("uuid", physical_interface_uuid) if physical_interface_uuid else KVPair("name", physical_interface)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def validate_interface_description(interface_descriptions):
    interface_descriptions = [
        {
            "interfaceID": interface_description.get("interface_id"),
            "description": interface_description.get("description"),
        }
        for interface_description in interface_descriptions
    ]

    return interface_descriptions


if __name__ == "__main__":
    main()
