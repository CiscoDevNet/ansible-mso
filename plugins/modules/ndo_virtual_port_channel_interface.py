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
module: ndo_virtual_port_channel_interface
short_description: Manage Virtual Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Virtual Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Gaspard Micol (@gmicol)
options:
    template:
        description:
        - The name of the template.
        - The template must be a fabric resource template.
        type: str
        required: true
    virtual_port_channel_interface:
        description:
        - The name of the Virtual Port Channel Interface.
        type: str
        aliases: [ name, virtual_port_channel, vpc ]
    virtual_port_channel_interface_uuid:
        description:
        - The UUID of the Virtual Port Channel Interface.
        - This parameter can be used instead of O(virtual_port_channel_interface)
          when an existing Virtual Port Channel Interface is updated.
        - This parameter is required when parameter O(virtual_port_channel_interface) is updated.
        type: str
        aliases: [ uuid, virtual_port_channel_uuid, vpc_uuid ]
    description:
        description:
        - The description of the Virtual Port Channel Interface.
        type: str
    node_1:
        description:
        - The first node ID.
        type: str
    node_2:
        description:
        - The second node ID.
        type: str
    interfaces_node_1:
        description:
        - The list of used Interface IDs for the first node.
        - Ranges of Interface IDs can be used.
        - This parameter is required during creation.
        type: list
        elements: str
        aliases: [ interfaces_1, members_1 ]
    interfaces_node_2:
        description:
        - The list of used Interface IDs for the second node.
        - Ranges of Interface IDs can be used.
        - This parameter is required during creation.
        type: list
        elements: str
        aliases: [ interfaces_2, members_2 ]
    interface_policy_group_uuid:
        description:
        - The UUID of the Port Channel Interface Policy Group.
        - An Port Channel Interface Policy Group must be attached required during creation.
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
            node:
                description:
                - The node ID.
                type: str
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
- name: Create a new Virtual Port Channel Interface
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    description: My Ansible Port Channel
    virtual_port_channel_interface: ansible_virtual_port_channel_interface
    node_1: 101
    node_2: 102
    interfaces_node_1:
      - 1/1
      - 1/10-11
    interfaces_node_2:
      - 1/2
    interface_policy_group:
      name: ansible_policy_group
      template: ansible_fabric_policy_template
    interface_descriptions:
      - node: 101
        interface_id: 1/1
        description: My first Ansible Interface for first node
      - node: 101
        interface_id: 1/10
        description: My second Ansible Interface for first node
      - node: 101
        interface_id: 1/11
        description: My third Ansible Interface for first node
      - node: 102
        interface_id: 1/2
        description: My first Ansible Interface for second node
    state: present

- name: Update Virtual Port Channel Interface's name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface: ansible_virtual_port_channel_interface_changed
    virtual_port_channel_interface_uuid: 0134c73f-4427-4109-9eea-5110ecdf10ea
    state: present

- name: Query an Virtual Port Channel Interface using it's name in the template
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface: ansible_virtual_port_channel_interface_changed
    state: query
  register: query_one

- name: Query an Virtual Port Channel Interface using it's uuid in the template
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface_uuid: 0134c73f-4427-4109-9eea-5110ecdf10ea
    state: query
  register: query_one_uuid

- name: Query all Virtual Port Channel Interfaces in the template
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query
  register: query_all

- name: Delete an Virtual Port Channel Interface using it's name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface: ansible_virtual_port_channel_interface_changed
    state: absent

- name: Delete an Virtual Port Channel Interface using it's uuid
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface_uuid: 0134c73f-4427-4109-9eea-5110ecdf10ea
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        virtual_port_channel_interface=dict(type="str", aliases=["name", "virtual_port_channel", "vpc"]),
        virtual_port_channel_interface_uuid=dict(type="str", aliases=["uuid", "virtual_port_channel_uuid", "vpc_uuid"]),
        description=dict(type="str"),
        node_1=dict(type="str"),
        node_2=dict(type="str"),
        interfaces_node_1=dict(type="list", elements="str", aliases=["interfaces_1", "members_1"]),
        interfaces_node_2=dict(type="list", elements="str", aliases=["interfaces_2", "members_2"]),
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
                node=dict(type="str"),
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
            ["state", "absent", ["virtual_port_channel_interface", "virtual_port_channel_interface_uuid"], True],
            ["state", "present", ["virtual_port_channel_interface", "virtual_port_channel_interface_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    virtual_port_channel_interface = module.params.get("virtual_port_channel_interface")
    virtual_port_channel_interface_uuid = module.params.get("virtual_port_channel_interface_uuid")
    description = module.params.get("description")
    node_1 = module.params.get("node_1")
    node_2 = module.params.get("node_2")
    interfaces_node_1 = module.params.get("interfaces_node_1")
    if interfaces_node_1:
        interfaces_node_1 = ",".join(interfaces_node_1)
    interfaces_node_2 = module.params.get("interfaces_node_2")
    if interfaces_node_2:
        interfaces_node_2 = ",".join(interfaces_node_2)
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Virtual Port Channel Interface"

    path = "/fabricResourceTemplate/template/virtualPortChannels"
    existing_virtual_port_channel_interfaces = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("virtualPortChannels", [])
    if virtual_port_channel_interface or virtual_port_channel_interface_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_virtual_port_channel_interfaces,
            [KVPair("uuid", virtual_port_channel_interface_uuid) if virtual_port_channel_interface_uuid else KVPair("name", virtual_port_channel_interface)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_virtual_port_channel_interfaces

    if state == "present":

        if interface_policy_group and not interface_policy_group_uuid:
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", interface_policy_group.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            interface_policy_group_uuid = fabric_policy_template.get_interface_policy_group_uuid(interface_policy_group.get("name"))

        if match:
            if virtual_port_channel_interface and match.details.get("name") != virtual_port_channel_interface:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=virtual_port_channel_interface))
                match.details["name"] = virtual_port_channel_interface

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if node_1 is not None and match.details.get("node1Details", {}).get("node") != node_1:
                ops.append(dict(op="replace", path="{0}/{1}/node1Details/node".format(path, match.index), value=node_1))
                match.details["node1Details"]["node"] = node_1

            if node_2 is not None and match.details.get("node2Details", {}).get("node") != node_2:
                ops.append(dict(op="replace", path="{0}/{1}/node2Details/node".format(path, match.index), value=node_2))
                match.details["node2Details"]["node"] = node_2

            if interface_policy_group_uuid and match.details.get("policy") != interface_policy_group_uuid:
                ops.append(dict(op="replace", path="{0}/{1}/policy".format(path, match.index), value=interface_policy_group_uuid))
                match.details["policy"] = interface_policy_group_uuid

            if interfaces_node_1 and interfaces_node_1 != match.details.get("node1Details", {}).get("memberInterfaces"):
                ops.append(dict(op="replace", path="{0}/{1}/node1Details/memberInterfaces".format(path, match.index), value=interfaces_node_1))
                match.details["node1Details"]["memberInterfaces"] = interfaces_node_1

            if interfaces_node_2 and interfaces_node_2 != match.details.get("node2Details", {}).get("memberInterfaces"):
                ops.append(dict(op="replace", path="{0}/{1}/node2Details/memberInterfaces".format(path, match.index), value=interfaces_node_2))
                match.details["node2Details"]["memberInterfaces"] = interfaces_node_2

            if interface_descriptions:
                interface_descriptions = [
                    {
                        "nodeID": interface.get("node"),
                        "interfaceID": interface.get("interface_id"),
                        "description": interface.get("description"),
                    }
                    for interface in interface_descriptions
                ]
                if interface_descriptions != match.details.get("interfaceDescriptions"):
                    ops.append(dict(op="replace", path="{0}/{1}/interfaceDescriptions".format(path, match.index), value=interface_descriptions))
                    match.details["interfaceDescriptions"] = interface_descriptions
            elif interface_descriptions == [] and match.details["interfaceDescriptions"]:
                ops.append(dict(op="remove", path="{0}/{1}/interfaceDescriptions".format(path, match.index)))

            mso.sanitize(match.details)

        else:
            payload = {
                "name": virtual_port_channel_interface,
                "node1Details": {
                    "node": node_1,
                    "memberInterfaces": interfaces_node_1,
                },
                "node2Details": {
                    "node": node_2,
                    "memberInterfaces": interfaces_node_2,
                },
                "policy": interface_policy_group_uuid,
            }
            if description is not None:
                payload["description"] = description
            if interface_descriptions:
                payload["interfaceDescriptions"] = [
                    {
                        "nodeID": interface.get("node"),
                        "interfaceID": interface.get("interface_id"),
                        "description": interface.get("description"),
                    }
                    for interface in interface_descriptions
                ]

            ops.append(dict(op="add", path="{0}/-".format(path), value=payload))

            mso.sanitize(payload)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        virtual_port_channel_interfaces = response.get("fabricResourceTemplate", {}).get("template", {}).get("virtualPortChannels", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            virtual_port_channel_interfaces,
            [KVPair("uuid", virtual_port_channel_interface_uuid) if virtual_port_channel_interface_uuid else KVPair("name", virtual_port_channel_interface)],
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
