#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ndo_port_channel_interface
short_description: Manage Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Gaspard Micol (@gmicol)
options:
    template:
        description:
        - The name of the template.
        - The template must be a Fabric Resource template.
        type: str
        required: true
    port_channel_interface:
        description:
        - The name of the Port Channel Interface.
        type: str
        aliases: [ name, port_channel ]
    port_channel_interface_uuid:
        description:
        - The UUID of the Port Channel Interface.
        - This parameter can be used instead of O(port_channel_interface)
          when an existing Virtual Port Channel Interface is updated.
        - This parameter is required when parameter O(port_channel_interface) is updated.
        type: str
        aliases: [ uuid, port_channel_uuid ]
    description:
        description:
        - The description of the Port Channel Interface.
        type: str
    node:
        description:
        - The node ID.
        - This is only required when creating a new Port Channel Interface.
        type: str
    interfaces:
        description:
        - The list of used Interface IDs.
        - Ranges of Interface IDs can be used.
        - This is only required when creating a new Port Channel Interface.
        type: list
        elements: str
        aliases: [ members ]
    interface_policy_group_uuid:
        description:
        - The UUID of the Port Channel Interface Setting Policy.
        - This is only required when creating a new Port Channel Interface.
        type: str
        aliases: [ policy_uuid, interface_policy_uuid, interface_setting_uuid ]
    interface_policy_group:
        description:
        - The name of the Port Channel Interface Policy Group.
        - This parameter can be used instead of O(interface_policy_group_uuid).
        - If both parameter are used, O(interface_policy_group) will be ignored.
        type: dict
        suboptions:
            name:
                description:
                - The name of the Port Channel Interface Policy Group.
                type: str
            template:
                description:
                - The name of the template in which the Port Channel Interface Policy Group has been created.
                type: str
        aliases: [ policy, interface_policy, interface_setting ]
    interface_descriptions:
        description:
        - The list of interface descriptions.
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
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new Port Channel Interface
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    description: My Ansible Port Channel
    port_channel_interface: ansible_port_channel_interface
    node: 101
    interfaces:
      - 1/1
      - 1/10-11
    interface_policy_group:
      name: ansible_policy_group
      template: ansible_fabric_policy_template
    interface_descriptions:
      - interface_id: 1/1
        description: My first Ansible Interface
      - interface_id: 1/10
        description: My second Ansible Interface
      - interface_id: 1/11
        description: My third Ansible Interface
    state: present

- name: Update a Port Channel Interface's name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface_changed
    port_channel_interface_uuid: 0135c73f-4427-4109-9eea-5110ecdf10ea
    state: present

- name: Query a Port Channel Interface using its name in the template
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface_changed
    state: query
  register: query_one

- name: Query a Port Channel Interface using its UUID in the template
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface_uuid: 0135c73f-4427-4109-9eea-5110ecdf10ea
    state: query
  register: query_one

- name: Query all Port Channel Interfaces in the template
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query
  register: query_all

- name: Delete a Port Channel Interface using its name
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface_changed
    state: absent

- name: Delete a Port Channel Interface using its UUID
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface_uuid: 0135c73f-4427-4109-9eea-5110ecdf10ea
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    format_interface_descriptions,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        port_channel_interface=dict(type="str", aliases=["name", "port_channel"]),
        port_channel_interface_uuid=dict(type="str", aliases=["uuid", "port_channel_uuid"]),
        description=dict(type="str"),
        node=dict(type="str"),
        interfaces=dict(type="list", elements="str", aliases=["members"]),
        interface_policy_group=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
            ),
            aliases=["policy", "interface_policy", "interface_setting"],
        ),
        interface_policy_group_uuid=dict(type="str", aliases=["policy_uuid", "interface_policy_uuid", "interface_setting_uuid"]),
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

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["port_channel_interface", "port_channel_interface_uuid"], True],
            ["state", "present", ["port_channel_interface", "port_channel_interface_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    port_channel_interface = module.params.get("port_channel_interface")
    port_channel_interface_uuid = module.params.get("port_channel_interface_uuid")
    description = module.params.get("description")
    node = module.params.get("node")
    interfaces = module.params.get("interfaces")
    if interfaces:
        interfaces = ",".join(interfaces)
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Port Channel Interface"

    path = "/fabricResourceTemplate/template/portChannels"
    existing_port_channel_interfaces = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", [])
    if port_channel_interface or port_channel_interface_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_port_channel_interfaces,
            [KVPair("uuid", port_channel_interface_uuid) if port_channel_interface_uuid else KVPair("name", port_channel_interface)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_port_channel_interfaces

    if state == "present":

        if interface_policy_group and not interface_policy_group_uuid:
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", interface_policy_group.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            interface_policy_group_uuid = fabric_policy_template.get_interface_policy_group_uuid(interface_policy_group.get("name"))

        if match:
            if port_channel_interface and match.details.get("name") != port_channel_interface:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=port_channel_interface))
                match.details["name"] = port_channel_interface

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            node_changed = False
            if node and match.details.get("node") != node:
                ops.append(dict(op="replace", path="{0}/{1}/node".format(path, match.index), value=node))
                match.details["node"] = node
                node_changed = True

            if interface_policy_group_uuid and match.details.get("policy") != interface_policy_group_uuid:
                ops.append(dict(op="replace", path="{0}/{1}/policy".format(path, match.index), value=interface_policy_group_uuid))
                match.details["policy"] = interface_policy_group_uuid

            if interfaces and interfaces != match.details.get("memberInterfaces"):
                ops.append(dict(op="replace", path="{0}/{1}/memberInterfaces".format(path, match.index), value=interfaces))
                match.details["memberInterfaces"] = interfaces

            if interface_descriptions or (node_changed and match.details.get("interfaceDescriptions")):
                if node_changed and interface_descriptions is None:
                    interface_descriptions = format_interface_descriptions(match.details["interfaceDescriptions"], node)
                else:
                    interface_descriptions = format_interface_descriptions(interface_descriptions, match.details["node"])
                if interface_descriptions != match.details.get("interfaceDescriptions"):
                    ops.append(dict(op="replace", path="{0}/{1}/interfaceDescriptions".format(path, match.index), value=interface_descriptions))
                    match.details["interfaceDescriptions"] = interface_descriptions
            elif interface_descriptions == [] and match.details["interfaceDescriptions"]:
                ops.append(dict(op="remove", path="{0}/{1}/interfaceDescriptions".format(path, match.index)))

            mso.sanitize(match.details)

        else:
            if not node:
                mso.fail_json(msg=("ERROR: Missing parameter 'node' for creating a Port Channel Interface"))
            payload = {"name": port_channel_interface, "node": node, "memberInterfaces": interfaces, "policy": interface_policy_group_uuid}
            if description is not None:
                payload["description"] = description
            if interface_descriptions:
                interface_descriptions = format_interface_descriptions(interface_descriptions, node)
                payload["interfaceDescriptions"] = interface_descriptions
            ops.append(dict(op="add", path="{0}/-".format(path), value=payload))

            mso.sanitize(payload)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        port_channel_interfaces = response.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            port_channel_interfaces,
            [KVPair("uuid", port_channel_interface_uuid) if port_channel_interface_uuid else KVPair("name", port_channel_interface)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
