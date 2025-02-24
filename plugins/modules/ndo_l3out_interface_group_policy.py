#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_interface_group_policy
short_description: Manage L3Out Interface Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Interface Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Shreyas Srish (@shrsr)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
    type: str
    aliases: [ l3out_template ]
  template_id:
    description:
    - The ID of the L3Out template.
    type: str
    aliases: [ l3out_template_id ]
  l3out:
    description:
    - The name of the L3Out.
    type: str
    aliases: [ l3out_name ]
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    type: str
  description:
    description:
    - The description of the L3Out Interface Group Policy.
    type: str
  name:
    description:
    - The name of the L3Out Interface Group Policy.
    type: str
    aliases: [ l3out_interface_group_policy ]
  interface_routing_policy:
    description:
    - The configuration of the Interface Routing Policy.
    - Providing an empty dictionary will remove the O(interface_routing_policy={}) from L3Out Interface Group Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the L3Out Interface Routing Policy.
        type: str
      template:
        description:
        - The template associated with the L3Out Interface Routing Policy.
        type: str
  interface_routing_policy_uuid:
    description:
    - The UUID of the L3Out Interface Routing Policy.
    - Providing an empty string will remove the O(interface_routing_policy_uuid="") from L3Out Interface Group Policy.
    type: str
  bfd:
    description:
    - The BFD configuration.
    - Providing an empty dictionary will remove the O(bfd={}) from the L3Out Interface Group Policy.
    type: dict
    suboptions:
      enable:
        description:
        - Whether BFD is enabled.
        type: bool
      authentication:
        description:
        - Whether BFD authentication is enabled.
        type: bool
      key_id:
        description:
        - The BFD key ID.
        type: int
      key:
        description:
        - The BFD key.
        type: str
  bfd_multi_hop:
    description:
    - The BFD multi-hop configuration.
    - Providing an empty dictionary will remove the O(bfd_multi_hop={}) from the L3Out Interface Group Policy.
    type: dict
    suboptions:
      enable:
        description:
        - Whether BFD multi-hop is enabled.
        type: bool
      authentication:
        description:
        - Whether BFD multi-hop authentication is enabled.
        type: bool
      key_id:
        description:
        - The BFD multi-hop key ID.
        type: int
      key:
        description:
        - The BFD multi-hop key.
        type: str
  ospf:
    description:
    - The OSPF configuration.
    - Providing an empty dictionary will remove the O(ospf={}) from the L3Out Interface Group Policy.
    type: dict
    suboptions:
      enable:
        description:
        - Whether OSPF is enabled.
        type: bool
      authentication_type:
        description:
        - The type of OSPF authentication.
        type: str
        choices: [ simple, md5, none ]
      key_id:
        description:
        - The OSPF key ID.
        type: int
      key:
        description:
        - The OSPF key.
        type: str
  qos_priority:
    description:
    - The QoS priority level.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
  custom_qos_policy:
    description:
    - The Custom QoS Policy configuration.
    - Providing an empty dictionary will remove the O(custom_qos_policy={}) from L3Out Interface Group Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Custom QoS Policy.
        type: str
      template:
        description:
        - The template associated with the Custom QoS Policy.
        type: str
  custom_qos_policy_uuid:
    description:
    - The UUID of the Custom QoS Policy.
    - Providing an empty string will remove the O(custom_qos_policy_uuid="") from L3Out Interface Group Policy.
    type: str
  state:
    description:
    - Determines the desired state of the resource.
    - Use C(absent) to remove the resource.
    - Use C(query) to list the resource.
    - Use C(present) to create or update the resource.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out object under the L3Out template.
- The O(interface_routing_policy) must exist before using it in the module.
  Use M(cisco.mso.ndo_l3out_interface_routing_policy) to create the L3Out Node Routing Policy.
- The O(custom_qos_policy) must exist before using it in the module.
  Use M(cisco.mso.ndo_tenant_custom_qos_policy) to create the Custom QoS Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_interface_routing_policy
- module: cisco.mso.ndo_tenant_custom_qos_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an L3Out interface group policy
  cisco.mso.ndo_l3out_interface_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: interface_group_policy_1
    description: Test description
    interface_routing_policy:
      name: ansible_l3out_interface_routing_policy
      template: ansible_tenant_template
    bfd:
      enable: true
      authentication: true
      key_id: 1
      key: TestKey
    bfd_multi_hop:
      enable: true
      authentication: true
      key_id: 1
      key: TestKey
    ospf:
      enable: true
      authentication_type: simple
      key_id: 1
      key: TestKey
    custom_qos_policy:
      template: ansible_tenant_template
      name: ansible_custom_qos_policy
    qos_priority: level1
    state: present

- name: Query an existing L3Out interface group policy with name
  cisco.mso.ndo_l3out_interface_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: interface_group_policy_1
    state: query
  register: query_with_name

- name: Query all existing L3Out interface group policies under l3out
  cisco.mso.ndo_l3out_interface_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    state: query

- name: Delete an existing L3Out interface group policy with name
  cisco.mso.ndo_l3out_interface_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: interface_group_policy_1
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
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none, get_object_identifier
from ansible_collections.cisco.mso.plugins.module_utils.constants import QOS_LEVEL


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_uuid=dict(type="str"),
        description=dict(type="str"),
        name=dict(type="str", aliases=["l3out_interface_group_policy"]),
        interface_routing_policy=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
            ),
            required_together=[
                ["name", "template"],
            ],
        ),
        interface_routing_policy_uuid=dict(type="str"),
        bfd=dict(
            type="dict",
            options=dict(
                enable=dict(type="bool"),
                authentication=dict(type="bool"),
                key_id=dict(type="int"),
                key=dict(type="str", no_log=True),
            ),
        ),
        bfd_multi_hop=dict(
            type="dict",
            options=dict(
                enable=dict(type="bool"),
                authentication=dict(type="bool"),
                key_id=dict(type="int"),
                key=dict(type="str", no_log=True),
            ),
        ),
        ospf=dict(
            type="dict",
            options=dict(
                enable=dict(type="bool"),
                authentication_type=dict(type="str", choices=["simple", "md5", "none"]),
                key_id=dict(type="int"),
                key=dict(type="str", no_log=True),
            ),
        ),
        qos_priority=dict(type="str", choices=QOS_LEVEL),
        custom_qos_policy=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
            ),
            required_together=[
                ["name", "template"],
            ],
        ),
        custom_qos_policy_uuid=dict(type="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["template", "template_id"], True],
            ["state", "query", ["template", "template_id"], True],
            ["state", "absent", ["template", "template_id"], True],
            ["state", "present", ["l3out", "l3out_uuid"], True],
            ["state", "query", ["l3out", "l3out_uuid"], True],
            ["state", "absent", ["l3out", "l3out_uuid"], True],
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
        mutually_exclusive=[
            ["interface_routing_policy", "interface_routing_policy_uuid"],
            ["custom_qos_policy", "custom_qos_policy_uuid"],
        ],
    )

    mso = MSOModule(module)

    template_identifier = get_object_identifier(module.params.get("template_id"), module.params.get("template"))
    l3out_identifier = get_object_identifier(module.params.get("l3out_uuid"), module.params.get("l3out"))
    name = module.params.get("name")
    description = module.params.get("description")
    interface_routing_policy = module.params.get("interface_routing_policy")
    interface_routing_policy_uuid = module.params.get("interface_routing_policy_uuid")
    bfd = module.params.get("bfd")
    bfd_multi_hop = module.params.get("bfd_multi_hop")
    ospf = module.params.get("ospf")
    qos_priority = module.params.get("qos_priority")
    custom_qos_policy = module.params.get("custom_qos_policy")
    custom_qos_policy_uuid = module.params.get("custom_qos_policy_uuid")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "l3out", template_identifier.get("name"), template_identifier.get("uuid"))
    mso_template.validate_template("l3out")
    object_description = "L3Out Interface Group Policy"

    existing_l3outs = mso_template.template.get("l3outTemplate", {}).get("l3outs", [])
    l3out_object = mso_template.get_object_by_key_value_pairs(
        "L3Out",
        existing_l3outs,
        [KVPair("uuid", l3out_identifier.get("uuid")) if l3out_identifier.get("uuid") else KVPair("name", l3out_identifier.get("name"))],
        True,
    )
    existing_interface_groups = l3out_object.details.get("interfaceGroups", [])
    if name:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_interface_groups,
            [KVPair("name", name)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_interface_groups

    if state != "query":
        interface_group_policy_path = "/l3outTemplate/l3outs/{0}/interfaceGroups/{1}".format(l3out_object.index, match.index if match else "-")

    ops = []

    attributes_dict = {"bfd": bfd, "bfdMultiHop": bfd_multi_hop, "ospf": ospf}
    empty_interface_routing_policy = False
    empty_custom_qos_policy = False

    if state == "present":
        check_authentication_requirements(mso, attributes_dict)
        mso_values = dict(
            name=name,
            description=description,
            interfaceRoutingPolicyRef=interface_routing_policy_uuid,
            qosPriority=qos_priority,
            qosRef=custom_qos_policy_uuid,
        )
        if interface_routing_policy:
            empty_interface_routing_policy = check_if_all_elements_are_none(list(interface_routing_policy.values()))
            if not empty_interface_routing_policy:
                mso_values["interfaceRoutingPolicyRef"] = mso_template.get_l3out_interface_routing_policy_uuid(
                    mso, interface_routing_policy.get("name"), interface_routing_policy.get("template")
                )
        if custom_qos_policy:
            empty_custom_qos_policy = check_if_all_elements_are_none(list(custom_qos_policy.values()))
            if not empty_custom_qos_policy:
                mso_values["qosRef"] = mso_template.get_custom_qos_policy_uuid(mso, custom_qos_policy.get("name"), custom_qos_policy.get("template"))

        if match:
            mso_values_remove = list()

            if (interface_routing_policy_uuid == "" or empty_interface_routing_policy) and match.details.get("interfaceRoutingPolicyRef"):
                mso_values_remove.append("interfaceRoutingPolicyRef")
            if (custom_qos_policy_uuid == "" or empty_custom_qos_policy) and match.details.get("qosRef"):
                mso_values_remove.append("qosRef")

            for attribute_name, attribute_dict in attributes_dict.items():
                if attribute_dict is not None:
                    attribute_is_empty = check_if_all_elements_are_none(list(attribute_dict.values()))

                    if match.details.get(attribute_name, {}).get("key", {}).get("ref"):
                        match.details[attribute_name]["key"].pop("ref", None)
                        mso.previous[attribute_name]["key"].pop("ref", None)
                        mso.existing[attribute_name]["key"].pop("ref", None)

                    if attribute_is_empty and match.details.get(attribute_name):
                        mso_values_remove.append(attribute_name)

                    elif not attribute_is_empty and not match.details.get(attribute_name):
                        update_mso_values_attributes_payload(mso_values, {attribute_name: attribute_dict})

                    elif not attribute_is_empty and match.details.get(attribute_name):
                        mso_values[(attribute_name, "enabled")] = attribute_dict.get("enable")
                        if attribute_name == "ospf":
                            mso_values[(attribute_name, "authType")] = attribute_dict.get("authentication_type")
                        else:
                            mso_values[(attribute_name, "authEnabled")] = attribute_dict.get("authentication")
                        mso_values[(attribute_name, "keyID")] = attribute_dict.get("key_id")

                        if attribute_dict.get("key") is not None:
                            if match.details.get(attribute_name, {}).get("key") is not None:
                                mso_values[(attribute_name, "key", "value")] = attribute_dict.get("key")
                            else:
                                mso_values[(attribute_name, "key")] = dict(value=attribute_dict.get("key"))

            append_update_ops_data(ops, match.details, interface_group_policy_path, mso_values, mso_values_remove)
            mso.sanitize(match.details, collate=True)
        else:
            update_mso_values_attributes_payload(mso_values, attributes_dict)
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=interface_group_policy_path, value=mso_values))

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=interface_group_policy_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3outs = response.get("l3outTemplate", {}).get("l3outs", [])
        l3out_object = mso_template.get_object_by_key_value_pairs(
            "L3Out",
            l3outs,
            [KVPair("uuid", l3out_identifier.get("uuid")) if l3out_identifier.get("uuid") else KVPair("name", l3out_identifier.get("name"))],
            True,
        )
        interface_groups = l3out_object.details.get("interfaceGroups", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            interface_groups,
            [KVPair("name", name)],
        )
        if match:
            for attribute_name in attributes_dict.keys():
                if match.details.get(attribute_name, {}).get("key", {}).get("ref"):
                    match.details[attribute_name]["key"].pop("ref", None)
            mso.existing = match.details
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def check_authentication_requirements(mso, attributes_dict):
    for attribute_name, attribute_dict in attributes_dict.items():
        if attribute_dict is not None:
            if (
                attribute_dict.get("enable") is True
                and (attribute_dict.get("authentication") is True or attribute_dict.get("authentication_type") in ["md5", "simple"])
                and (attribute_dict.get("key") is None or attribute_dict.get("key_id") is None)
            ):
                mso.fail_json(msg="key and key_id are required under {0}".format(attribute_name))
            elif (attribute_dict.get("enable") is not True) and (
                attribute_dict.get("authentication") is not None or attribute_dict.get("key") is not None or attribute_dict.get("key_id") is not None
            ):
                mso.fail_json(msg="{0} must be enabled in order to use authentication, key and key_id".format(attribute_name))


def update_mso_values_attributes_payload(mso_values, attributes_dict):
    for attribute_name, attribute_dict in attributes_dict.items():
        if attribute_dict is not None:
            if attribute_dict.get("enable") is not None:
                mso_values[attribute_name] = {
                    "enabled": attribute_dict.get("enable"),
                }
            if attribute_dict.get("enable") is True:
                if attribute_dict.get("authentication") is True:
                    mso_values[attribute_name].update(
                        {
                            "authEnabled": attribute_dict.get("authentication"),
                            "keyID": attribute_dict.get("key_id"),
                            "key": {"value": attribute_dict.get("key")},
                        }
                    )
                elif attribute_dict.get("authentication_type") in ["md5", "simple"]:
                    mso_values[attribute_name].update(
                        {
                            "authType": attribute_dict.get("authentication_type"),
                            "keyID": attribute_dict.get("key_id"),
                            "key": {"value": attribute_dict.get("key")},
                        }
                    )


if __name__ == "__main__":
    main()
