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
    member_interfaces:
        description:
        - The list of used Interface IDs.
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
                - The interface ID to which attach a description.
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
    member_interfaces:
      - 1/1
    interface_policy_uuid: ansible_port_channel_policy
    interface_descriptions:
      - interface_id: 1/1
        description: My first Ansible Interface
    state: present

- name: Query an Port Channel Interface with template_name
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    port_channel_interface: ansible_port_channel_interface
    state: query

- name: Query all IPort Channel Interfaces in the template
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query

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
        port_channel_interface=dict(type="str", aliases=["name", "port_channel"]),
        port_channel_interface_uuid=dict(type="str", aliases=["uuid", "port_channel_uuid"]),
        description=dict(type="str"),
        node=dict(type="str"),
        member_interfaces=dict(type="list", elements="str", aliases=["members"]),
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
            ["state", "absent", ["port_channel_interface"]],
            ["state", "present", ["port_channel_interface"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    port_channel_interface = module.params.get("port_channel_interface")
    port_channel_interface_uuid = module.params.get("port_channel_interface_uuid")
    description = module.params.get("description")
    node = module.params.get("node")
    member_interfaces = module.params.get("member_interfaces")
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
            if match.details.get("name") != port_channel_interface:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/name".format(path, match.index),
                        value=port_channel_interface,
                    )
                )
                match.details["name"] = port_channel_interface

            if match.details.get("description") != description:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/description".format(path, match.index),
                        value=description,
                    )
                )
                match.details["description"] = description

            if match.details.get("node") != node:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/node".format(path, match.index),
                        value=node,
                    )
                )
                match.details["node"] = node

            if match.details.get("memberInterfaces") != member_interfaces:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/memberInterfaces".format(path, match.index),
                        value=",".join(member_interfaces),
                    )
                )
                match.details["memberInterfaces"] = member_interfaces

            if match.details.get("policy") != interface_policy_uuid:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/policy".format(path, match.index),
                        value=interface_policy_uuid,
                    )
                )
                match.details["policy"] = interface_policy_uuid

            if interface_descriptions is not None and match.details.get("interfaceDescriptions") != interface_descriptions:
                ops.append(
                    dict(
                        op="replace",
                        path="{0}/{1}/interfaceDescriptions".format(path, match.index),
                        value=[
                            {
                                "nodeID": node,
                                "interfaceID": interface.get("interface_id"),
                                "description": interface.get("description"),
                            }
                            for interface in interface_descriptions
                        ],
                    )
                )
                match.details["interfaceDescriptions"] = interface_descriptions

            mso.sanitize(match.details)

        else:
            payload = {
                "name": port_channel_interface,
                "description": description,
                "node": node,
                "memberInterfaces": ",".join(member_interfaces),
                "policy": interface_policy_uuid,
            }

            if interface_descriptions:
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
