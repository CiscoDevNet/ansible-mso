#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>

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
module: ndo_node_profile
short_description: Manage Node Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Node Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Samita Bhattacharjee (@samiib)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Resource Policy template.
    type: str
    required: true
  name:
    description:
    - The name of the Node Profile.
    type: str
    aliases: [ node_profile ]
  uuid:
    description:
    - The UUID of the Node Profile.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ node_profile_uuid ]
  description:
    description:
    - The description of the Node Profile.
    type: str
  nodes:
    description:
    - The list of node IDs to associate with the Node Profile.
    - This parameter is required when O(state=present).
    type: list
    elements: int
  node_setting_uuid:
    description:
    - The UUID of the Node Setting to associate with the Node Profile.
    - This parameter or O(node_setting) is required when O(state=present).
    type: str
  node_setting:
    description:
    - The Node Setting to associate with the Node Profile.
    - This parameter or O(node_setting_uuid) is required when O(state=present).
    type: dict
    suboptions:
      name:
        description:
        - The name of the Node Setting.
        type: str
        required: true
      template:
        description:
        - The name of the Fabric Policy template that contains the Node Setting.
        type: str
        required: true
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) and O(node_setting) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Fabric Resource Policy template.
  Use M(cisco.mso.ndo_node_setting) to create the Node Setting.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_node_setting
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new Node Profile
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    name: node_profile_1
    nodes: [101, 102]
    node_setting:
      name: node_setting_1
      template: fabric_template
    state: present
  register: create_node_profile_1

- name: Update the name and Node Setting of a Node Policy using UUID
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    name: node_profile_1_updated
    nodes: [101, 102]
    node_setting_uuid: "{{ create_node_setting_2.current.uuid }}"
    state: present
  register: update_node_profile_1

- name: Query an existing Node Profile using UUID
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    uuid: "{{ create_node_profile_1.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query an existing Node Profile using name
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    name: node_profile_1_updated
    state: query
  register: query_with_name

- name: Query all Node Profiles
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    state: query
  register: query_all

- name: Delete an existing Node Profile using UUID
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    uuid: "{{ create_node_profile_1.current.uuid }}"
    state: absent

- name: Delete an existing Node Profile using Name
  cisco.mso.ndo_node_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_resource_template
    name: node_profile_1_updated
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import (
    append_update_ops_data,
)
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        name=dict(type="str", aliases=["node_profile"]),
        uuid=dict(type="str", aliases=["node_profile_uuid"]),
        description=dict(type="str"),
        nodes=dict(type="list", elements="int"),
        node_setting_uuid=dict(type="str"),
        node_setting=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
            ["state", "present", ["node_setting_uuid", "node_setting"], True],
            ["state", "present", ["nodes"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    nodes = module.params.get("nodes")
    if nodes:
        nodes = [str(node) for node in nodes]
    node_setting_uuid = module.params.get("node_setting_uuid")
    node_setting = module.params.get("node_setting")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Node Profile"
    path = "/fabricResourceTemplate/template/nodeProfiles"
    node_profile_path = None

    existing_node_profiles = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("nodeProfiles") or []

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_node_profiles,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            node_profile_path = "{0}/{1}".format(path, match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_node_profiles

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if node_setting and not node_setting_uuid:
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", node_setting.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            node_setting_uuid = fabric_policy_template.get_node_settings_object(uuid=None, name=node_setting.get("name"), fail_module=True).details.get("uuid")

        mso_values = dict(
            name=name,
            description=description,
            nodes=nodes,
            policy=node_setting_uuid,
        )

        if mso.existing and match:
            proposed_payload = copy.deepcopy(match.details)
            append_update_ops_data(ops, proposed_payload, node_profile_path, mso_values)
            mso.sanitize(proposed_payload, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=node_profile_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        node_profiles = response.get("fabricResourceTemplate", {}).get("template", {}).get("nodeProfiles") or []
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            node_profiles,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
