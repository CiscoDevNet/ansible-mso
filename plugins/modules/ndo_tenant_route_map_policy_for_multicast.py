#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_route_map_policy_for_multicast
short_description: Manage Route Map Policy for Multicast in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Route Map Policy for Multicast in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the tenant template.
    type: str
    aliases: [ tenant_template ]
    required: true
  name:
    description:
    - The name of the Route Map Policy for Multicast.
    type: str
    aliases: [ igmp_interface_policy ]
  uuid:
    description:
    - The UUID of the Route Map Policy for Multicast.
    - This parameter is required when the Route Map Policy for Multicast O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the Route Map Policy for Multicast.
    - Providing an empty string will remove the O(description="") from the Route Map Policy for Multicast.
    type: str
  route_map_for_multicast_entries:
    description:
    - The list of Route Map entries for Multicast.
    - Atleast one route-map entry needs to be defined.
    - Required when creating a new Route Map Policy for Multicast.
    type: list
    elements: dict
    suboptions:
      order:
        description:
        - The order of the Route Map entry.
        - The valid range is from C(0) to C(65535).
        type: int
      group_ip:
        description:
        - The group IP address.
        - Group IP must be a valid IPv4/IPv6 IP, refer to tooltip
        type: str
      source_ip:
        description:
        - The source IP address.
        - Source IP must be a valid IPv4/IPv6 IP, refer to tooltip
        type: str
        aliases: [ source_ip_address, src_ip ]
      rp_ip:
        description:
        - The RP IP address.
        - RP IP can be in IP address format or with subnet mask. Subnet mask has to be 32 for IPv4 and 128 for IPv6.
        type: str
        aliases: [ rp_ip_address ]
      action:
        description:
        - The action to be taken.
        - Defaults to C(permit) when unset during creation.
        type: str
        choices: [ permit, deny ]
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
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""

"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["tenant_template"]),
        name=dict(type="str", aliases=["igmp_snooping_policy"]),
        uuid=dict(type="str"),
        description=dict(type="str"),
        route_map_for_multicast_entries=dict(  # route_map_for_multicast_entries required when creating and API gives good error message... what to do ?
            type="list",
            elements="dict",
            options=dict(
                order=dict(type="int", required=True),
                group_ip=dict(type="str", required=True),
                source_ip=dict(type="str", required=True, aliases=["source_ip_address", "src_ip"]),
                rp_ip=dict(type="str", aliases=["rp_ip_address"]),
                action=dict(type="str", choices=["permit", "deny"]),
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
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    route_map_for_multicast_entries = module.params.get("route_map_for_multicast_entries")
    state = module.params.get("state")

    template_object = MSOTemplate(mso, "tenant", template)
    template_object.validate_template("tenantPolicy")

    mld_interface_policies = template_object.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", [])
    object_description = "Route Map Policy for Multicast"

    if state in ["query", "absent"] and mld_interface_policies == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = mld_interface_policies
    elif mld_interface_policies and (name or uuid):
        match = template_object.get_object_by_key_value_pairs(
            object_description, mld_interface_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            route_map_policy_for_multicast_attrs_path = "/tenantPolicyTemplate/template/mcastRouteMapPolicies/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if mso.existing:
            proposed_payload = copy.deepcopy(match.details)

            if name and mso.existing.get("name") != name:
                ops.append(dict(op="replace", path=route_map_policy_for_multicast_attrs_path + "/name", value=name))
                proposed_payload["name"] = name

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=route_map_policy_for_multicast_attrs_path + "/description", value=description))
                proposed_payload["description"] = description

            if route_map_for_multicast_entries is not None and mso.existing.get("mcastRtMapEntryList") != route_map_for_multicast_entries:
                ops.append(dict(op="replace", path=route_map_policy_for_multicast_attrs_path + "/mcastRtMapEntryList", value=route_map_for_multicast_entries))
                proposed_payload["mcastRtMapEntryList"] = route_map_for_multicast_entries

            mso.sanitize(proposed_payload, collate=True)
        else:
            payload = {
                "name": name,
                "description": description,
            }
            if route_map_for_multicast_entries:
                route_map_list = []
                for entry in route_map_for_multicast_entries:
                    route_map_list.append(
                        dict(
                            order=entry["order"],
                            group=entry["group_ip"],
                            source=entry["source_ip"],
                            rp=entry.get("rp_ip"),
                            action=entry.get("action", "permit"),
                        )
                    )
                payload["routeMapEntries"] = route_map_list
            mso.sanitize(payload)
            ops.append(dict(op="add", path="/tenantPolicyTemplate/template/mcastRouteMapPolicies/-", value=mso.sent))

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=route_map_policy_for_multicast_attrs_path))

    if not module.check_mode and ops:
        response_object = mso.request(template_object.template_path, method="PATCH", data=ops)
        mld_snooping_policies = response_object.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", [])
        match = template_object.get_object_by_key_value_pairs(
            object_description, mld_snooping_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
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
