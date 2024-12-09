#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_igmp_interface_policy
short_description: Manage Internet Group Management Protocol (IGMP) Interface Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage IGMP Interface Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
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
    - The name of the IGMP Interface Policy.
    type: str
    aliases: [ igmp_interface_policy ]
  uuid:
    description:
    - The UUID of the IGMP Interface Policy.
    - This parameter is required when the IGMP Interface Policy O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the IGMP Interface Policy.
    - Providing an empty string will remove the O(description="") from the IGMP Interface Policy.
    type: str
  version3_asm:
    description:
    - Enable or disable IGMP version 3 ASM.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
    aliases: [ allow_version3_asm ]
  fast_leave:
    description:
    - Enable or disable fast leave.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  report_link_local_groups:
    description:
    - Enable or disable reporting link-local groups.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  igmp_version:
    description:
    - The IGMP version of the IGMP Interface Policy.
    - Defaults to C(v2) when unset during creation.
    type: str
    choices: [ v2, v3 ]
  group_timeout:
    description:
    - The group timeout value in seconds.
    - Defaults to C(260) when unset during creation.
    - The valid range is from C(3) to C(65535).
    type: int
  query_interval:
    description:
    - The query interval value in seconds.
    - Defaults to C(125) when unset during creation.
    - The valid range is from C(1) to C(18000).
    type: int
  query_response_interval:
    description:
    - The query response interval value in seconds.
    - Defaults to C(10) when unset during creation.
    - The valid range is from C(1) to C(25).
    type: int
  last_member_count:
    description:
    - The last member query count value.
    - Defaults to C(2) when unset during creation.
    - The valid range is from C(1) to C(5).
    type: int
  last_member_response_time:
    description:
    - The last member query response time value in seconds.
    - Defaults to C(1) when unset during creation.
    - The valid range is from C(1) to C(25).
    type: int
  startup_query_count:
    description:
    - The startup query count value.
    - Defaults to C(2) when unset during creation.
    - The valid range is from C(1) to C(10).
    type: int
  startup_query_interval:
    description:
    - The startup query interval value in seconds.
    - Defaults to C(31) when unset during creation.
    - The valid range is from C(1) to C(18000).
    type: int
  querier_timeout:
    description:
    - The querier timeout value in seconds.
    - Defaults to C(255) when unset during creation.
    - The valid range is from C(1) to C(65535).
    type: int
  robustness_variable:
    description:
    - The robustness variable value.
    - Defaults to C(2) when unset during creation.
    - The valid range is from C(1) to C(7).
    type: int
  state_limit_route_map_uuid:
    description:
    - The state limit route map name.
    type: str
    aliases: [ state_limit_route_map ]
  report_policy_route_map_uuid:
    description:
    - The report policy route map name.
    type: str
    aliases: [ report_policy_route_map ]
  static_report_route_map_uuid:
    description:
    - The static report route map name.
    type: str
    aliases: [ static_report_route_map ]
  maximum_multicast_entries:
    description:
    - The maximum multicast entries value.
    - Defaults to C(4294967295) when unset during creation.
    - The valid range is from C(1) to C(4294967295).
    type: int
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
- The O(state_limit_route_map_uuid), O(report_policy_route_map_uuid), O(static_report_route_map_uuid) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_tenant_route_map_policy_for_multicast) to create the Route Map Policy for Multicast.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an IGMP Interface Policy
  cisco.mso.ndo_tenant_igmp_interface_policy:
    template: TestTenantTemplate
    name: TestIGMPInterfacePolicy
    description: Test Description
    version3_asm: enabled
    fast_leave: enabled
    report_link_local_groups: enabled
    igmp_version: v3
    group_timeout: 260
    query_interval: 125
    query_response_interval: 10
    last_member_count: 2
    last_member_response_time: 1
    startup_query_count: 2
    startup_query_interval: 31
    querier_timeout: 255
    robustness_variable: 2
    state_limit_route_map_uuid: TestStateLimitRouteMap
    report_policy_route_map_uuid: TestReportPolicyRouteMap
    static_report_route_map_uuid: TestStaticReportRouteMap
    maximum_multicast_entries: 4294967295
    state: present
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
        version3_asm=dict(type="str", choices=["enabled", "disabled"]),
        fast_leave=dict(type="str", choices=["enabled", "disabled"]),
        report_link_local_groups=dict(type="str", choices=["enabled", "disabled"]),
        igmp_version=dict(type="str", choices=["v2", "v3"]),
        group_timeout=dict(type="int"),
        query_interval=dict(type="int"),
        query_response_interval=dict(type="int"),
        last_member_count=dict(type="int"),
        last_member_response_time=dict(type="int"),
        startup_query_count=dict(type="int"),
        startup_query_interval=dict(type="int"),
        querier_timeout=dict(type="int"),
        robustness_variable=dict(type="int"),
        state_limit_route_map_uuid=dict(type="str", aliases=["state_limit_route_map"]),
        report_policy_route_map_uuid=dict(type="str", aliases=["report_policy_route_map"]),
        static_report_route_map_uuid=dict(type="str", aliases=["static_report_route_map"]),
        maximum_multicast_entries=dict(type="int"),
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
    version3_asm = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("version3_asm"))
    fast_leave = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("fast_leave"))
    report_link_local_groups = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("report_link_local_groups"))
    igmp_version = module.params.get("igmp_version")
    group_timeout = module.params.get("group_timeout")
    query_interval = module.params.get("query_interval")
    query_response_interval = module.params.get("query_response_interval")
    last_member_count = module.params.get("last_member_count")
    last_member_response_time = module.params.get("last_member_response_time")
    startup_query_count = module.params.get("startup_query_count")
    startup_query_interval = module.params.get("startup_query_interval")
    querier_timeout = module.params.get("querier_timeout")
    robustness_variable = module.params.get("robustness_variable")
    state_limit_route_map_uuid = module.params.get("state_limit_route_map_uuid")
    report_policy_route_map_uuid = module.params.get("report_policy_route_map_uuid")
    static_report_route_map_uuid = module.params.get("static_report_route_map_uuid")
    maximum_multicast_entries = module.params.get("maximum_multicast_entries")
    state = module.params.get("state")

    template_object = MSOTemplate(mso, "tenant", template)
    template_object.validate_template("tenantPolicy")

    mld_interface_policies = template_object.template.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpInterfacePolicies", [])
    object_description = "IGMP Interface Policy"

    if state in ["query", "absent"] and mld_interface_policies == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = mld_interface_policies
    elif mld_interface_policies and (name or uuid):
        match = template_object.get_object_by_key_value_pairs(
            object_description, mld_interface_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            igmp_interface_policy_attrs_path = "/tenantPolicyTemplate/template/igmpInterfacePolicies/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if mso.existing:
            proposed_payload = copy.deepcopy(match.details)

            if name and mso.existing.get("name") != name:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/name", value=name))
                proposed_payload["name"] = name

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/description", value=description))
                proposed_payload["description"] = description

            if version3_asm and mso.existing.get("enableV3Asm") != version3_asm:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/enableV3Asm", value=version3_asm))
                proposed_payload["enableV3Asm"] = version3_asm

            if fast_leave and mso.existing.get("enableFastLeaveControl") != fast_leave:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/enableFastLeaveControl", value=fast_leave))
                proposed_payload["enableFastLeaveControl"] = fast_leave

            if report_link_local_groups and mso.existing.get("enableReportLinkLocalGroups") != report_link_local_groups:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/enableReportLinkLocalGroups", value=report_link_local_groups))
                proposed_payload["enableReportLinkLocalGroups"] = report_link_local_groups

            if igmp_version and mso.existing.get("igmpQuerierVersion") != igmp_version:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/igmpQuerierVersion", value=igmp_version))
                proposed_payload["igmpQuerierVersion"] = igmp_version

            if group_timeout and mso.existing.get("groupTimeout") != group_timeout:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/groupTimeout", value=group_timeout))
                proposed_payload["groupTimeout"] = group_timeout

            if query_interval and mso.existing.get("queryInterval") != query_interval:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/queryInterval", value=query_interval))
                proposed_payload["queryInterval"] = query_interval

            if query_response_interval and mso.existing.get("queryResponseInterval") != query_response_interval:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/queryResponseInterval", value=query_response_interval))
                proposed_payload["queryResponseInterval"] = query_response_interval

            if last_member_count and mso.existing.get("lastMemberCount") != last_member_count:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/lastMemberCount", value=last_member_count))
                proposed_payload["lastMemberCount"] = last_member_count

            if last_member_response_time and mso.existing.get("lastMemberResponseInterval") != last_member_response_time:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/lastMemberResponseInterval", value=last_member_response_time))
                proposed_payload["lastMemberResponseInterval"] = last_member_response_time

            if startup_query_count and mso.existing.get("startQueryCount") != startup_query_count:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/startQueryCount", value=startup_query_count))
                proposed_payload["startQueryCount"] = startup_query_count

            if startup_query_interval and mso.existing.get("startQueryInterval") != startup_query_interval:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/startQueryInterval", value=startup_query_interval))
                proposed_payload["startQueryInterval"] = startup_query_interval

            if querier_timeout and mso.existing.get("querierTimeout") != querier_timeout:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/querierTimeout", value=querier_timeout))
                proposed_payload["querierTimeout"] = querier_timeout

            if robustness_variable and mso.existing.get("robustnessFactor") != robustness_variable:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/robustnessFactor", value=robustness_variable))
                proposed_payload["robustnessFactor"] = robustness_variable

            if state_limit_route_map_uuid and mso.existing.get("stateLimitRouteMapRef") != state_limit_route_map_uuid:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/stateLimitRouteMapRef", value=state_limit_route_map_uuid))
                proposed_payload["stateLimitRouteMapRef"] = state_limit_route_map_uuid

            if report_policy_route_map_uuid and mso.existing.get("reportPolicyRouteMapRef") != report_policy_route_map_uuid:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/reportPolicyRouteMapRef", value=report_policy_route_map_uuid))
                proposed_payload["reportPolicyRouteMapRef"] = report_policy_route_map_uuid

            if static_report_route_map_uuid and mso.existing.get("staticReportRouteMapRef") != static_report_route_map_uuid:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/staticReportRouteMapRef", value=static_report_route_map_uuid))
                proposed_payload["staticReportRouteMapRef"] = static_report_route_map_uuid

            if maximum_multicast_entries and mso.existing.get("maximumMulticastEntries") != maximum_multicast_entries:
                ops.append(dict(op="replace", path=igmp_interface_policy_attrs_path + "/maximumMulticastEntries", value=maximum_multicast_entries))
                proposed_payload["maximumMulticastEntries"] = maximum_multicast_entries

            mso.sanitize(proposed_payload, collate=True)
        else:
            payload = {
                "name": name,
                "description": description,
                "enableV3Asm": version3_asm,
                "enableFastLeaveControl": fast_leave,
                "enableReportLinkLocalGroups": report_link_local_groups,
                "igmpQuerierVersion": igmp_version,
                "groupTimeout": group_timeout,
                "queryInterval": query_interval,
                "queryResponseInterval": query_response_interval,
                "lastMemberCount": last_member_count,
                "lastMemberResponseInterval": last_member_response_time,
                "startQueryCount": startup_query_count,
                "startQueryInterval": startup_query_interval,
                "querierTimeout": querier_timeout,
                "robustnessFactor": robustness_variable,
                "stateLimitRouteMapRef": state_limit_route_map_uuid,
                "reportPolicyRouteMapRef": report_policy_route_map_uuid,
                "staticReportRouteMapRef": static_report_route_map_uuid,
                "maximumMulticastEntries": maximum_multicast_entries,
            }

            mso.sanitize(payload)
            ops.append(dict(op="add", path="/tenantPolicyTemplate/template/igmpInterfacePolicies/-", value=mso.sent))

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=igmp_interface_policy_attrs_path))

    if not module.check_mode and ops:
        response_object = mso.request(template_object.template_path, method="PATCH", data=ops)
        mld_snooping_policies = response_object.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpInterfacePolicies", [])
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
