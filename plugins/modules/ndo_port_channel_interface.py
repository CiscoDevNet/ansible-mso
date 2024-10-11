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
        - The template must be a tenant template.
        type: str
        required: true
    port_channel_interface:
        description:
        - The name of the Port Channel Interface.
        type: str
        aliases: [ name, port_channel ]
    port_channel_interface_uuid:
        description:
        - The uuid of the Port Channel Interface.
        - This parameter is required when the O(port_channel_interface) needs to be updated.
        type: str
        aliases: [ uuid, port_channel_uuid ]
    description:
        description:
        - The description of the Port Channel Interface.
        type: str
    node:
        description:
        - The node ID.
        type: str
    interfaces:
        description:
        - The list of used Interface IDs.
        - Ranges of Interface IDs can be used.
        type: list
        elements: str
        aliases: [ members ]
    interface_policy:
        description:
        - The name of the Port Channel Interface Setting Policy.
        type: str
        aliases: [ policy, pc_policy ]
    interface_policy_uuid:
        description:
        - The UUID of the Port Channel Interface Setting Policy.
        type: str
        aliases: [ policy_uuid, pc_policy_uuid ]
    interface_descriptions:
        description:
        - The list of descriptions for each interface.
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
    interface_policy_uuid: ansible_port_channel_policy
    interface_descriptions:
      - interface_id: 1/1
        description: My first Ansible Interface
      - interface_id: 1/10
        description: My second Ansible Interface
      - interface_id: 1/11
        description: My third Ansible Interface
    state: present

- name: Query an Port Channel Interface with template_name
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface
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

- name: Delete an Port Channel Interface
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface
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
        port_channel_interface=dict(type="str", aliases=["name", "port_channel"]),
        port_channel_interface_uuid=dict(type="str", aliases=["uuid", "port_channel_uuid"]),
        description=dict(type="str"),
        node=dict(type="str"),
        interfaces=dict(type="list", elements="str", aliases=["members"]),
        interface_policy=dict(type="str", aliases=["policy", "pc_policy"]),
        interface_policy_uuid=dict(type="str", aliases=["policy_uuid", "pc_policy_uuid"]),
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
            ["state", "absent", ["template", "port_channel_interface"]],
            ["state", "present", ["template", "port_channel_interface"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    port_channel_interface = module.params.get("port_channel_interface")
    port_channel_interface_uuid = module.params.get("port_channel_interface_uuid")
    description = module.params.get("description")
    node = module.params.get("node")
    interfaces = ",".join(module.params.get("interfaces")) if module.params.get("interfaces") else None
    interface_policy = module.params.get("interface_policy")
    interface_policy_uuid = module.params.get("interface_policy_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Port Channel Interface"

    path = "/fabricResourceTemplate/template/portChannels"
    existing_template = mso_template.template.get("fabricResourceTemplate", {}).get("template", {})
    existing_port_channel_interfaces = existing_template.get("portChannels") if existing_template.get("portChannels") else []
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
            if port_channel_interface and match.details.get("name") != port_channel_interface:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=port_channel_interface))
                match.details["name"] = port_channel_interface

            if description and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            node_changed = False
            if node and match.details.get("node") != node:
                ops.append(dict(op="replace", path="{0}/{1}/node".format(path, match.index), value=node))
                match.details["node"] = node
                node_changed = True

            if interface_policy_uuid and match.details.get("policy") != interface_policy_uuid:
                ops.append(dict(op="replace", path="{0}/{1}/policy".format(path, match.index), value=interface_policy_uuid))
                match.details["policy"] = interface_policy_uuid

            if interfaces and match.details.get("memberInterfaces") != interfaces:
                interface_ids, errors_interfaces = lookup_valid_interfaces(interfaces)
                if errors_interfaces:
                    mso.fail_json(msg=("Invalid interface inputs, {0}".format(errors_interfaces)))
                else:
                    ops.append(dict(op="replace", path="{0}/{1}/memberInterfaces".format(path, match.index), value=interfaces))
                    match.details["memberInterfaces"] = interfaces
            else:
                interface_ids, errors_interfaces = lookup_valid_interfaces(match.details.get("memberInterfaces"))

            if interface_descriptions or (node_changed and match.details.get("interfaceDescriptions")):
                if node_changed and interface_descriptions is None:
                    interface_descriptions = [
                        {
                            "nodeID": node,
                            "interfaceID": interface.get("interfaceID"),
                            "description": interface.get("description"),
                        }
                        for interface in match.details["interfaceDescriptions"]
                    ]
                else:
                    interface_descriptions = [
                        {
                            "nodeID": match.details["node"],
                            "interfaceID": interface.get("interface_id"),
                            "description": interface.get("description"),
                        }
                        for interface in interface_descriptions
                    ]
                    error_descriptions = []
                    for interface_description in interface_descriptions:
                        if interface_description["interfaceID"] not in interface_ids:
                            error_descriptions.append(interface_description["interfaceID"])
                    if error_descriptions:
                        mso.fail_json(
                            msg=("Interface IDs with description {0} not in list of current interfaces {1}".format(error_descriptions, list(interface_ids)))
                        )
                if interface_descriptions != match.details.get("interfaceDescriptions"):
                    ops.append(dict(op="replace", path="{0}/{1}/interfaceDescriptions".format(path, match.index), value=interface_descriptions))
                    match.details["interfaceDescriptions"] = interface_descriptions
            elif interface_descriptions == [] and match.details["interfaceDescriptions"]:
                ops.append(dict(op="remove", path="{0}/{1}/interfaceDescriptions".format(path, match.index)))

            mso.sanitize(match.details)

        else:
            config = {"node": node, "memberInterfaces": interfaces, "policy": interface_policy_uuid}
            missing_required_attributes = []
            for attribute_name, attribute_value in config.items():
                if not attribute_value:
                    missing_required_attributes.append(attribute_name)
            if missing_required_attributes:
                mso.fail_json(msg=("Missing required attributes {0} for creating a Port Channel Interface".format(missing_required_attributes)))
            else:
                payload = {"name": port_channel_interface} | config
                interface_ids, errors_interfaces = lookup_valid_interfaces(payload["memberInterfaces"])
                if errors_interfaces:
                    mso.fail_json(msg=("Invalid interface inputs, {0}".format(errors_interfaces)))
                if description:
                    payload["description"] = description
                if interface_descriptions:
                    error_descriptions = []
                    for interface_description in interface_descriptions:
                        if interface_description["interface_id"] not in interface_ids:
                            error_descriptions.append(interface_description["interface_id"])
                    if error_descriptions:
                        mso.fail_json(
                            msg=("Interface IDs with description {0} not in list of current interfaces {1}".format(error_descriptions, list(interface_ids)))
                        )
                    payload["interfaceDescriptions"] = [
                        {
                            "nodeID": node,
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
        port_channel_interfaces = template.get("portChannels") if template.get("portChannels") else []
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
