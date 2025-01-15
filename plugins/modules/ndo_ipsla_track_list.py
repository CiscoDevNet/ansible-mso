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
module: ndo_ipsla_track_list
short_description: Manage IPSLA Track Lists on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage IP Service Level Agreement (SLA) Track Lists on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Samita Bhattacharjee (@samitab)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    type: str
    required: true
  ipsla_track_list:
    description:
    - The name of the IPSLA Track List.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of the IPSLA Track List.
    type: str
  ipsla_track_list_uuid:
    description:
    - The UUID of the IPSLA Track List.
    - This parameter is required when the O(ipsla_track_list) attribute needs to be updated.
    type: str
    aliases: [ uuid ]
  type:
    description:
    - The IPSLA Track List type used for determining up or down status.
    - Use C(percentage) to track a percentage of O(members) 
    - This parameter is required when creating the IPSLA Track List.
    type: str
    choices: [ percentage, weight ]
  threshold_up:
    description:
    - The IPSLA Track List percentage or weight up threshold.
    - The value must be in the range 0 - 100 when O(type) is C(percentage).
    - The value must be in the range 0 - 255 when O(type) is C(weight).
    - The value must be greater than or equal to O(threshold_down).
    - The default value is 1.
    type: int
    aliases: [ up ]
  threshold_down:
    description:
    - The IPSLA Track List percentage or weight down threshold.
    - The value must be in the range 0 - 100 when O(type) is C(percentage).
    - The value must be in the range 0 - 255 when O(type) is C(weight).
    - The value must be less than or equal to O(threshold_up).
    - The default value is 0.
    type: int
    aliases: [ down ]
  members:
    description:
    - The IPSLA Track List members.
    - Providing a new list of O(members) will replace the existing members from the IPSLA Track List.
    - Providing an empty list will remove the O(members=[]) from the IPSLA Track List.
    type: list
    elements: dict
    suboptions:
      destination_ip:
        description:
        - The destination IP of the member.
        - Must be a valid IPv4 or IPv6 address.
        type: str
        required: true
        aliases: [ ip ]
      weight:
        description:
        - The weight of the member.
        - The default value is 10.
        type: int
      ipsla_monitoring_policy:
        description:
        - The IPSLA Monitoring Policy to use for the member.
        type: str
        required: true
      scope:
        description:
        - The name of the BD or L3Out used as the scope for the member.
        type: str
        required: true
      scope_type:
        description:
        - The scope type of the member.
        type: str
        required: true
        choices: [ bd, l3out ]
      schema:
        description:
        - The name of the Schema associated with the BD scope.
        - This parameter is only required when the O(scope_type) is C(bd).
        type: str
      template:
        description:
        - The name of the Template associated with the BD or L3Out scope.
        type: str
        required: true
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: present
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(ipsla_monitoring_policy) must exist before adding O(members).
  Use M(cisco.mso.ndo_ipsla_monitoring_policy) to create an IPSLA Monitoring Policy.
- The O(scope) as either a BD or L3Out must exist before adding O(members).
  Use M(cisco.mso.ndo_l3out_template) to create an L3Out.
  Use M(cisco.mso.mso_schema_template_bd) to create a BD.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_ipsla_monitoring_policy
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.mso_schema_template_bd
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new IPSLA Track List
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list: ansible_test_ipsla_track_list
    description: Example track list
    type: percentage
    threshold_up: 10
    threshold_down: 2
    members:
      - destination_ip: 1.1.1.1
        scope: ansible_test_bd
        scope_type: bd
        schema: ansible_test_schema
        template: ansible_test_template
        ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
      - destination_ip: 2001:0000:130F:0000:0000:09C0:876A:130B
        scope: ansible_test_l3out
        scope_type: l3out
        template: ansible_test_template
        ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
    state: present

- name: Query an IPSLA Track List with name
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list: ansible_test_ipsla_track_list
    state: query
  register: query_one

- name: Query an IPSLA Track List with UUID
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list_uuid: "{{ query_one.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Query all IPSLA Track Lists in the template
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Remove all members from an IPSLA Track List
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list: ansible_test_ipsla_track_list
    type: percentage
    members: []
    state: present

- name: Delete an IPSLA Track List with name
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list: ansible_test_ipsla_track_list
    state: absent

- name: Delete an IPSLA Track List with UUID
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list_uuid: "{{ query_one.current.uuid }}"
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


def get_ipsla_monitoring_policy_uuid(mso_template, name, uuid=None):
    existing_ipsla_policies = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaMonitoringPolicies", [])
    match = mso_template.get_object_by_key_value_pairs(
        "IPSLA Monitoring Policy",
        existing_ipsla_policies,
        [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        fail_module=True,
    )
    if match:
        return match.details.get("uuid")


def get_bd_uuid(mso: MSOModule, schema, template, bd):
    # Get schema objects
    _, _, schema_obj = mso.query_schema(schema)
    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)
    # Get BD
    bds = [b.get("name") for b in schema_obj.get("templates")[template_idx]["bds"]]
    if bd not in bds:
        mso.fail_json(msg="Provided BD '{0}' does not exist. Existing BDs: {1}".format(bd, ", ".join(bds)))
    return schema_obj.get("templates")[template_idx]["bds"][bds.index(bd)].get("uuid")


def get_l3out_uuid(mso: MSOModule, l3out_template, name, uuid=None):
    l3out_template_object = MSOTemplate(mso, "l3out", l3out_template)
    l3out_template_object.validate_template("l3out")
    l3outs = l3out_template_object.template.get("l3outTemplate", {}).get("l3outs", [])
    match = l3out_template_object.get_object_by_key_value_pairs(
        "L3Out",
        l3outs,
        [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        fail_module=True,
    )
    if match:
        return match.details.get("uuid")


def format_track_list_members(mso: MSOModule, mso_template, members):
    track_list_members = []
    for member in members:
        scope_name = member.get("scope")
        scope_type = member.get("scope_type")
        schema = member.get("schema")
        template = member.get("template")
        weight = member.get("weight")
        track_member = {
            "destIP": member.get("destination_ip"),
            "scope": (get_bd_uuid(mso, schema, template, scope_name) if scope_type == "bd" else get_l3out_uuid(mso, template, scope_name)),
            "scopeType": scope_type,
            "ipslaMonitoringRef": get_ipsla_monitoring_policy_uuid(mso_template, member.get("ipsla_monitoring_policy")),
        }
        track_member = {"trackMember": track_member}
        if weight is not None:
            track_member["weight"] = weight
        track_list_members.append(track_member)
    return track_list_members


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            ipsla_track_list=dict(type="str", aliases=["name"]),
            ipsla_track_list_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            type=dict(type="str", choices=["percentage", "weight"]),
            threshold_up=dict(type="int"),
            threshold_down=dict(type="int"),
            members=dict(
                type="list",
                elements="dict",
                options=dict(
                    destination_ip=dict(type="str", aliases=["ip"], required=True),
                    ipsla_monitoring_policy=dict(type="str", required=True),
                    scope=dict(type="str", required=True),
                    scope_type=dict(type="str", choices=["bd", "l3out"], required=True),
                    schema=dict(type="str"),
                    template=dict(type="str", required=True),
                    weight=dict(type="int"),
                ),
                required_if=[
                    ["scope_type", "bd", ["schema"]],
                ],
            ),
            state=dict(type="str", choices=["absent", "query", "present"], default="present"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ipsla_track_list", "ipsla_track_list_uuid"], True],
            ["state", "present", ["ipsla_track_list", "ipsla_track_list_uuid"], True],
            ["state", "present", ["type"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    ipsla_track_list = module.params.get("ipsla_track_list")
    description = module.params.get("description")
    ipsla_track_list_uuid = module.params.get("ipsla_track_list_uuid")
    type = module.params.get("type")
    thresholds = {
        "down": module.params.get("threshold_down"),
        "up": module.params.get("threshold_up"),
    }
    members = module.params.get("members")
    state = module.params.get("state")

    # Validate
    valid_upper = 100
    valid_lower = 0
    if type == "weight":
        valid_upper = 255
    for threshold_key, threshold_value in thresholds.items():
        if threshold_value is not None and threshold_value not in range(valid_lower, valid_upper):
            mso.fail_json(
                msg="Invalid value provided for threshold_{0}: {1}; it must be in the range {2} - {3}".format(
                    threshold_key, threshold_value, valid_lower, valid_upper
                )
            )

    if thresholds["down"] is not None and thresholds["up"] is not None:
        if thresholds["down"] > thresholds["up"]:
            mso.fail_json(
                msg="Invalid value provided for threshold_down: {0}; it must be less than or equal to threshold_up: {1}".format(
                    thresholds["down"], thresholds["up"]
                )
            )

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")
    object_description = "IPSLA Track List"
    path = "/tenantPolicyTemplate/template/ipslaTrackLists"

    existing_ipsla_track_lists = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaTrackLists", [])
    if ipsla_track_list or ipsla_track_list_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_ipsla_track_lists,
            [(KVPair("uuid", ipsla_track_list_uuid) if ipsla_track_list_uuid else KVPair("name", ipsla_track_list))],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_ipsla_track_lists

    if state == "present":
        if ipsla_track_list_uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, ipsla_track_list_uuid))

        mso_values = {
            "name": ipsla_track_list,
            "description": description,
            "type": type,
            type + "Up": thresholds["up"],
            type + "Down": thresholds["down"],
        }
        if members is not None:
            mso_values["trackListMembers"] = format_track_list_members(mso, mso_template, members)
        if match:
            update_path = "{0}/{1}".format(path, match.index)
            append_update_ops_data(ops, match.details, update_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        ipsla_track_lists = response.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaTrackLists", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            ipsla_track_lists,
            [(KVPair("uuid", ipsla_track_list_uuid) if ipsla_track_list_uuid else KVPair("name", ipsla_track_list))],
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
