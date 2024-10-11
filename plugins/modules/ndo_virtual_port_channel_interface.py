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
short_description: Manage Virtual Port Channel Interfaces_1 on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Virtual Port Channel Interfaces_1 on Cisco Nexus Dashboard Orchestrator (NDO).
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
        - The uuid of the Virtual Port Channel Interface.
        - This parameter is required when the O(virtual_port_channel_interface) needs to be updated.
        type: str
        aliases: [ uuid, virtual_port_channel_uuid, vpc_uuid ]
    description:
        description:
        - The description of the Port Channel Interface.
        type: str
    node_1:
        description:
        - The first node ID.
        type: str
    node_2:
        description:
        - The second node ID.
        type: str
    interfaces_1:
        description:
        - The list of used Interface IDs for the first node.
        - Ranges of Interface IDs can be used.
        type: list
        elements: str
        aliases: [ members_1 ]
    interfaces_2:
        description:
        - The list of used Interface IDs for the second node.
        - Ranges of Interface IDs can be used.
        type: list
        elements: str
        aliases: [ members_2 ]
    interface_policy:
        description:
        - The name of the Virtual Port Channel Interface Setting Policy.
        type: str
        aliases: [ policy, vpc_policy ]
    interface_policy_uuid:
        description:
        - The UUID of the Port Channel Interface Setting Policy.
        type: str
        aliases: [ policy_uuid, vpc_policy_uuid ]
    interface_descriptions:
        description:
        - The list of descriptions for each interface.
        type: list
        elements: dict
        suboptions:
            node:
                description:
                - The node ID
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
    interfaces_1:
      - 1/1
      - 1/10-11
    interfaces_2:
      - 1/2
    interface_policy_uuid: ansible_port_channel_policy
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

- name: Query an Virtual Port Channel Interface with template_name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface: ansible_virtual_port_channel_interface
    state: query
  register: query_one

- name: Query all Virtual Port Channel Interfaces in the template
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query
  register: query_all

- name: Delete an Virtual Port Channel Interface
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    virtual_port_channel_interface: ansible_virtual_port_channel_interface
    state: absent
"""

RETURN = r"""
"""

import copy
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)


def lookup_valid_interfaces(interfaces):
    interface_ids = []
    errors_interfaces = []
    modified_interfaces = interfaces.replace(" ", "").split(",")
    for interface in modified_interfaces:
        if re.fullmatch(r"((\d+/)+\d+-\d+$)", interface):
            slots = interface.rsplit("/", 1)[0]
            range_start, range_stop = interface.rsplit("/", 1)[1].split("-")
            if int(range_stop) > int(range_start):
                for x in range(int(range_start), int(range_stop) + 1):
                    interface_ids.append("{0}/{1}".format(slots, x))
            else:
                errors_interfaces.append(interface)
        elif re.fullmatch(r"((\d+/)+\d+$)", interface):
            interface_ids.append(interface)
        else:
            errors_interfaces.append(interface)
    return set(interface_ids), errors_interfaces


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        virtual_port_channel_interface=dict(type="str", aliases=["name", "virtual_port_channel", "vpc"]),
        virtual_port_channel_interface_uuid=dict(type="str", aliases=["uuid", "virtual_port_channel_uuid", "vpc_uuid"]),
        description=dict(type="str"),
        node_1=dict(type="str"),
        node_2=dict(type="str"),
        interfaces_1=dict(type="list", elements="str", aliases=["members_1"]),
        interfaces_2=dict(type="list", elements="str", aliases=["members_2"]),
        interface_policy=dict(type="str", aliases=["policy", "vpc_policy"]),
        interface_policy_uuid=dict(type="str", aliases=["policy_uuid", "vpc_policy_uuid"]),
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
            ["state", "absent", ["template", "virtual_port_channel_interface"]],
            ["state", "present", ["template", "virtual_port_channel_interface"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    virtual_port_channel_interface = module.params.get("virtual_port_channel_interface")
    virtual_port_channel_interface_uuid = module.params.get("virtual_port_channel_interface_uuid")
    description = module.params.get("description")
    node_1 = module.params.get("node_1")
    node_2 = module.params.get("node_2")
    interfaces_1 = ",".join(module.params.get("interfaces_1")) if module.params.get("interfaces_1") else None
    interfaces_2 = ",".join(module.params.get("interfaces_2")) if module.params.get("interfaces_2") else None
    interface_policy = module.params.get("interface_policy")
    interface_policy_uuid = module.params.get("interface_policy_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Virtual Port Channel Interface"

    path = "/fabricResourceTemplate/template/virtualPortChannels"
    existing_template = mso_template.template.get("fabricResourceTemplate", {}).get("template", {})
    existing_virtual_port_channel_interfaces = existing_template.get("virtualPortChannels") if existing_template.get("virtualPortChannels") else []
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

        if interface_policy and not interface_policy_uuid:
            pc_policy_groups = mso.query_obj("portchannelpolicygroups").get("items", [])
            if isinstance(pc_policy_groups, list) and len(pc_policy_groups) > 0:
                for policy_group in pc_policy_groups:
                    if interface_policy == policy_group["spec"]["name"]:
                        interface_policy_uuid = policy_group["spec"]["uuid"]
                        break
                if not interface_policy_uuid:
                    mso.fail_json(msg="Port Channel policy '{0}' not found in the list of existing Port Channel policy groups".format(interface_policy))
            else:
                mso.fail_json(msg="No existing Port Channel policy")

        if match:
            if virtual_port_channel_interface and match.details.get("name") != virtual_port_channel_interface:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=virtual_port_channel_interface))
                match.details["name"] = virtual_port_channel_interface

            if description and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if node_1 and match.details.get("node1Details", {}).get("node") != node_1:
                ops.append(dict(op="replace", path="{0}/{1}/node1Details/node".format(path, match.index), value=node_1))
                match.details["node1Details"]["node"] = node_1

            if node_2 and match.details.get("node2Details", {}).get("node") != node_2:
                ops.append(dict(op="replace", path="{0}/{1}/node2Details/node".format(path, match.index), value=node_2))
                match.details["node2Details"]["node"] = node_2

            if interface_policy_uuid and match.details.get("policy") != interface_policy_uuid:
                ops.append(dict(op="replace", path="{0}/{1}/policy".format(path, match.index), value=interface_policy_uuid))
                match.details["policy"] = interface_policy_uuid

            if interfaces_1 and match.details.get("node1Details", {}).get("memberInterfaces") != interfaces_1:
                interface_ids, errors_interfaces = lookup_valid_interfaces(interfaces_1)
                if errors_interfaces:
                    mso.fail_json(msg=("Invalid interface inputs for node 1, {0}".format(errors_interfaces)))
                else:
                    ops.append(dict(op="replace", path="{0}/{1}/node1Details/memberInterfaces".format(path, match.index), value=interfaces_1))
                    match.details["node1Details"]["memberInterfaces"] = interfaces_1
            else:
                interface_ids, errors_interfaces = lookup_valid_interfaces(match.details.get("node1Details", {}).get("memberInterfaces"))

            if interfaces_2 and match.details.get("node1Details", {}).get("memberInterfaces") != interfaces_2:
                interface_ids, errors_interfaces = lookup_valid_interfaces(interfaces_2)
                if errors_interfaces:
                    mso.fail_json(msg=("Invalid interface inputs for node 2, {0}".format(errors_interfaces)))
                else:
                    ops.append(dict(op="replace", path="{0}/{1}/node2Details/memberInterfaces".format(path, match.index), value=interfaces_2))
                    match.details["node2Details"]["memberInterfaces"] = interfaces_2
            else:
                interface_ids, errors_interfaces = lookup_valid_interfaces(match.details.get("node2Details", {}).get("memberInterfaces"))

            if interface_descriptions:
                interface_descriptions = [
                    {
                        "nodeID": interface.get("node"),
                        "interfaceID": interface.get("interface_id"),
                        "description": interface.get("description"),
                    }
                    for interface in interface_descriptions
                ]
                error_members_descriptions, error_nodes_descriptions = [], set()
                node_ids = set(match.details["node1Details"]["node"], match.details["node2Details"]["node"])
                for interface_description in interface_descriptions:
                    if interface_description["interfaceID"] not in interface_ids:
                        error_members_descriptions.append(interface_description["interfaceID"])
                    if interface_description["nodeID"] not in node_ids:
                        error_nodes_descriptions.add(interface_description["nodeID"])
                if error_members_descriptions:
                    mso.fail_json(
                        msg=("Interface IDs with description {0} not in list of current interfaces {1}".format(error_members_descriptions, list(interface_ids)))
                    )
                if error_nodes_descriptions:
                    mso.fail_json(
                        msg=("node IDs with description {0} not in list of current nodes {1}".format(list(error_nodes_descriptions), list(node_ids)))
                    )
                if interface_descriptions != match.details.get("interfaceDescriptions"):
                    ops.append(dict(op="replace", path="{0}/{1}/interfaceDescriptions".format(path, match.index), value=interface_descriptions))
                    match.details["interfaceDescriptions"] = interface_descriptions
            elif interface_descriptions == [] and match.details["interfaceDescriptions"]:
                ops.append(dict(op="remove", path="{0}/{1}/interfaceDescriptions".format(path, match.index)))

            mso.sanitize(match.details)

        else:
            config = {
                "node1Details": {
                    "node": node_1,
                    "memberInterfaces": interfaces_1,
                },
                "node2Details": {
                    "node": node_2,
                    "memberInterfaces": interfaces_2,
                },
                "policy": interface_policy_uuid,
            }
            missing_required_attributes = []
            for attribute_name, attribute_value in config.items():
                if attribute_name in ["node1Details", "node2Details"]:
                    for subattribute_name in ["node", "memberInterfaces"]:
                        if not attribute_value.get(subattribute_name):
                            missing_required_attributes.append("{0} in {1}".format(subattribute_name, attribute_name))
                if not attribute_value:
                    missing_required_attributes.append(attribute_name)
            if missing_required_attributes:
                mso.fail_json(msg=("Missing required attributes {0} for creating a Port Channel Interface".format(missing_required_attributes)))
            else:
                payload = {"name": virtual_port_channel_interface} | config
                interfaces = ",".join([interfaces_1, interfaces_2])
                interface_ids, errors_interfaces = lookup_valid_interfaces(interfaces)
                if errors_interfaces:
                    mso.fail_json(msg=("Invalid interface inputs, {0}".format(errors_interfaces)))
                if description:
                    payload["description"] = description
                if interface_descriptions:
                    error_members_descriptions, error_nodes_descriptions = [], set()
                    for interface_description in interface_descriptions:
                        if interface_description["interface_id"] not in interface_ids:
                            error_members_descriptions.append(interface_description["interface_id"])
                        if interface_description["node"] not in set(node_1, node_2):
                            error_nodes_descriptions.add(interface_description["node"])
                    if error_members_descriptions:
                        mso.fail_json(
                            msg=(
                                "Interface IDs with description {0} not in list of current interfaces {1}".format(
                                    error_members_descriptions, list(interface_ids)
                                )
                            )
                        )
                    if error_nodes_descriptions:
                        mso.fail_json(
                            msg=("Node IDs with description {0} not in list of current nodes {1}".format(list(error_nodes_descriptions), list(node_1, node_2)))
                        )
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
        template = response.get("fabricResourceTemplate", {}).get("template", {})
        virtual_port_channel_interfaces = template.get("virtualPortChannels") if template.get("virtualPortChannels") else []
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
