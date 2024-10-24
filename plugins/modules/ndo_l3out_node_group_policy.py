#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_node_group_policy
short_description: Manage L3Out Node Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Node Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
    type: str
    aliases: [ l3out_template ]
    required: true
  l3out:
    description:
    - The name of the L3Out.
    type: str
    aliases: [ l3out_name ]
    required: true
  name:
    description:
    - The name of the L3Out Node Group Policy.
    type: str
    aliases: [ l3out_node_group_policy ]
  description:
    description:
    - The description of the L3Out Node Group Policy.
    type: str
  node_routing_policy:
    description:
    - The name of the L3Out Node Routing Policy.
    type: str
  bfd_multi_hop_authentication:
    description:
    - The Bidirectional Forwarding Detection (BFD) multi-hop authentication of the L3Out Node Group Policy.
    - To enable the O(bfd_multi_hop_authentication) BGP routing protocol must be configured on the L3Out.
    type: str
    choices: [ enabled, disabled ]
  bfd_multi_hop_key_id:
    description:
    - The BFD multi-hop key ID of the L3Out Node Group Policy.
    type: int
  bfd_multi_hop_key:
    description:
    - The BFD multi-hop key of the L3Out Node Group Policy.
    type: str
  target_dscp:
    description:
    - The DSCP Level of the L3Out Node Group Policy.
    type: str
    choices:
      - af11
      - af12
      - af13
      - af21
      - af22
      - af23
      - af31
      - af32
      - af33
      - af41
      - af42
      - af43
      - cs0
      - cs1
      - cs2
      - cs3
      - cs4
      - cs5
      - cs6
      - cs7
      - expedited_forwarding
      - unspecified
      - voice_admit
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
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out object under the L3Out template.
- The O(node_routing_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_node_routing_policy) to create the L3Out Node Routing Policy.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: present

- name: Update an existing L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    description: "Updated description"
    node_routing_policy: ans_node_policy_group_1
    bfd_multi_hop_authentication: enabled
    bfd_multi_hop_key_id: 1
    bfd_multi_hop_key: TestKey
    target_dscp: af11
    state: present

- name: Query a L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: query
  register: query_with_name

- name: Delete an existing L3Out node group policy with name
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import generate_api_endpoint


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["l3out_template"]),
        l3out=dict(type="str", required=True, aliases=["l3out_name"]),
        name=dict(type="str", aliases=["l3out_node_group_policy"]),
        description=dict(type="str"),
        node_routing_policy=dict(type="str"),
        bfd_multi_hop_authentication=dict(type="str", choices=["enabled", "disabled"]),
        bfd_multi_hop_key_id=dict(type="int"),
        bfd_multi_hop_key=dict(type="str", no_log=False),
        target_dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    l3out = module.params.get("l3out")
    name = module.params.get("name")
    description = module.params.get("description")
    node_routing_policy = module.params.get("node_routing_policy")
    bfd_multi_hop_authentication = module.params.get("bfd_multi_hop_authentication")
    bfd_multi_hop_key_id = module.params.get("bfd_multi_hop_key_id")
    bfd_multi_hop_key = module.params.get("bfd_multi_hop_key")
    target_dscp = TARGET_DSCP_MAP.get(module.params.get("target_dscp"))
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "l3out", template)
    mso_template.validate_template("l3out")

    l3out_object = mso_template.get_l3out_object(name=l3out, fail_module=True)
    l3out_node_group = mso_template.get_l3out_node_group(name, l3out_object.details)

    if name and l3out_node_group:
        mso.existing = mso.previous = copy.deepcopy(l3out_node_group.details)  # Query a specific object
    elif l3out_node_group:
        mso.existing = l3out_node_group  # Query all objects

    if state != "query":
        node_group_policy_path = "/l3outTemplate/l3outs/{0}/nodeGroups/{1}".format(l3out_object.index, l3out_node_group.index if l3out_node_group else "-")

    ops = []

    if state == "present":
        l3out_node_routing_policy_object = None
        if node_routing_policy:
            l3out_node_routing_policy_objects = mso.query_objs(
                generate_api_endpoint(
                    "templates/objects", **{"type": "l3OutNodePolGroup", "tenant-id": mso_template.template_summary.get("tenantId"), "include-common": "true"}
                )
            )
            l3out_node_routing_policy_object = mso_template.get_object_by_key_value_pairs(
                "L3Out Node Routing Policy", l3out_node_routing_policy_objects, [KVPair("name", node_routing_policy)], True
            )

        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=node_group_policy_path + "/description", value=description))
                proposed_payload["description"] = description

            if l3out_node_routing_policy_object and mso.existing.get("nodeRoutingPolicyRef") != l3out_node_routing_policy_object.details.get("uuid"):
                ops.append(
                    dict(op="replace", path=node_group_policy_path + "/nodeRoutingPolicyRef", value=l3out_node_routing_policy_object.details.get("uuid"))
                )
                proposed_payload["nodeRoutingPolicyRef"] = l3out_node_routing_policy_object.details.get("uuid")
            elif node_routing_policy == "" and mso.existing.get("nodeRoutingPolicyRef"):
                ops.append(dict(op="remove", path=node_group_policy_path + "/nodeRoutingPolicyRef"))
                proposed_payload.pop("nodeRoutingPolicyRef", None)

            if (bfd_multi_hop_authentication or bfd_multi_hop_key or bfd_multi_hop_key_id) and not mso.existing.get("bfdMultiHop"):
                ops.append(dict(op="replace", path=node_group_policy_path + "/bfdMultiHop", value=dict()))
                proposed_payload["bfdMultiHop"] = dict()

            if bfd_multi_hop_authentication is not None and mso.existing.get("bfdMultiHop", {}).get("authEnabled") is not (
                True if bfd_multi_hop_authentication == "enabled" else False
            ):
                ops.append(
                    dict(
                        op="replace",
                        path=node_group_policy_path + "/bfdMultiHop/authEnabled",
                        value=True if bfd_multi_hop_authentication == "enabled" else False,
                    )
                )
                proposed_payload["bfdMultiHop"]["authEnabled"] = True if bfd_multi_hop_authentication == "enabled" else False

            if bfd_multi_hop_key_id is not None and mso.existing.get("bfdMultiHop", {}).get("keyID") != bfd_multi_hop_key_id:
                ops.append(dict(op="replace", path=node_group_policy_path + "/bfdMultiHop/keyID", value=bfd_multi_hop_key_id))
                proposed_payload["bfdMultiHop"]["keyID"] = bfd_multi_hop_key_id

            if bfd_multi_hop_key is not None:
                ops.append(dict(op="replace", path=node_group_policy_path + "/bfdMultiHop/key", value=dict()))
                ops.append(dict(op="replace", path=node_group_policy_path + "/bfdMultiHop/key/value", value=bfd_multi_hop_key))
                proposed_payload["bfdMultiHop"]["key"] = dict(value=bfd_multi_hop_key)

            if target_dscp is not None and mso.existing.get("targetDscp") != target_dscp:
                ops.append(dict(op="replace", path=node_group_policy_path + "/targetDscp", value=target_dscp))
                proposed_payload["targetDscp"] = target_dscp

            mso.sanitize(proposed_payload, collate=True)

        else:
            payload = dict(name=name)

            if description:
                payload["description"] = description

            if l3out_node_routing_policy_object:
                payload["nodeRoutingPolicyRef"] = l3out_node_routing_policy_object.details.get("uuid")

            bfd_multi_hop = dict()

            if bfd_multi_hop_authentication is not None:
                bfd_multi_hop["authEnabled"] = True if bfd_multi_hop_authentication == "enabled" else False

            if bfd_multi_hop_key_id:
                bfd_multi_hop["keyID"] = bfd_multi_hop_key_id

            if bfd_multi_hop_key:
                bfd_multi_hop["key"] = dict(value=bfd_multi_hop_key)

            if bfd_multi_hop:
                payload["bfdMultiHop"] = bfd_multi_hop

            if target_dscp:
                payload["targetDscp"] = target_dscp

            mso.sanitize(payload)
            ops.append(dict(op="add", path=node_group_policy_path, value=payload))

        mso.existing = mso.proposed

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=node_group_policy_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(name=l3out, fail_module=True)
        l3out_node_group = mso_template.get_l3out_node_group(name, l3out_object.details)
        if l3out_node_group:
            mso.existing = l3out_node_group.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
