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
    - This parameter is required when creating the IPSLA Track List.
    type: str
    choices: [ percentage, weight ]
  threshold_up:
    description:
    - The IPSLA Track List percentage or weight up threshold.
    - The value must be in the range 0 - 100 when O(type=percentage).
    - The value must be in the range 0 - 255 when O(type=weight).
    - The value must be greater than or equal to O(threshold_down).
    - The default value is 1.
    type: int
    aliases: [ up ]
  threshold_down:
    description:
    - The IPSLA Track List percentage or weight down threshold.
    - The value must be in the range 0 - 100 when O(type=percentage).
    - The value must be in the range 0 - 255 when O(type=weight).
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
      ipsla_monitoring_policy_uuid:
        description:
        - The UUID of the IPSLA Monitoring Policy to use for the member.
        - This parameter can be used instead of O(members.ipsla_monitoring_policy).
        type: str
      ipsla_monitoring_policy:
        description:
        - The name IPSLA Monitoring Policy to use for the member.
        - This parameter can be used instead of O(members.ipsla_monitoring_policy_uuid).
        type: str
        aliases: [ ipsla_monitoring_policy_name ]
      scope_type:
        description:
        - The scope type of the member.
        type: str
        required: true
        choices: [ bd, l3out ]
      scope_uuid:
        description:
        - The UUID of the BD or L3Out used as the scope for the member.
        - This parameter can be used instead of O(members.scope).
        type: str
      scope:
        description:
        - The BD or L3Out used as the scope for the member.
        - This parameter can be used instead of O(members.scope_uuid).
        type: dict
        suboptions:
          name:
            description:
            - The name of the BD or L3Out used as the scope for the member.
            type: str
            required: true
          schema:
            description:
            - The name of the Schema associated with the BD scope.
            - This parameter is only required when the O(members.scope_type=bd).
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
- The O(members.ipsla_monitoring_policy) must exist before adding O(members).
  Use M(cisco.mso.ndo_ipsla_monitoring_policy) to create an IPSLA Monitoring Policy.
- The O(members.scope) as either a BD or L3Out must exist before adding O(members).
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
        scope_type: bd
        scope:
          name: ansible_test_bd
          template: ansible_test_template
          schema: ansible_test_schema
        ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
      - destination_ip: 2001:0000:130F:0000:0000:09C0:876A:130B
        scope_type: l3out
        scope:
          name: ansible_test_l3out
          template: ansible_test_template
        ipsla_monitoring_policy: ansible_test_ipsla_monitoring_policy
      - destination_ip: 1.1.1.2
        scope_type: l3out
        scope_uuid: "{{ l3out.current.uuid }}"
        ipsla_monitoring_policy_uuid: "{{ ipsla_monitoring_policy.current.uuid }}"
    state: present
    register: ipsla_track_list

- name: Update an IPSLA Track List name with UUID
  cisco.mso.ndo_ipsla_track_list:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    ipsla_track_list: ansible_test_ipsla_track_list_updated
    ipsla_track_list_uuid: "{{ ipsla_track_list.current.uuid }}"
    state: present
  register: ipsla_track_list_update

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
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
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
        dict(
            template=dict(type="str", required=True),
            ipsla_track_list=dict(type="str", aliases=["name"]),
            ipsla_track_list_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            type=dict(type="str", choices=["percentage", "weight"]),
            threshold_up=dict(type="int", aliases=["up"]),
            threshold_down=dict(type="int", aliases=["down"]),
            members=dict(
                type="list",
                elements="dict",
                options=dict(
                    destination_ip=dict(type="str", aliases=["ip"], required=True),
                    ipsla_monitoring_policy_uuid=dict(type="str"),
                    ipsla_monitoring_policy=dict(type="str", aliases=["ipsla_monitoring_policy_name"]),
                    scope_uuid=dict(type="str"),
                    scope=dict(
                        type="dict",
                        options=dict(
                            name=dict(type="str", required=True),
                            template=dict(type="str", required=True),
                            schema=dict(type="str"),
                        ),
                    ),
                    scope_type=dict(type="str", choices=["bd", "l3out"], required=True),
                    weight=dict(type="int"),
                ),
                mutually_exclusive=[
                    ("ipsla_monitoring_policy_uuid", "ipsla_monitoring_policy"),
                    ("scope_uuid", "scope"),
                ],
                required_one_of=[
                    ("ipsla_monitoring_policy_uuid", "ipsla_monitoring_policy"),
                    ("scope_uuid", "scope"),
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
    list_type = module.params.get("type")
    thresholds = {
        "down": module.params.get("threshold_down"),
        "up": module.params.get("threshold_up"),
    }
    members = module.params.get("members")
    state = module.params.get("state")

    # Validate
    valid_upper = 100
    valid_lower = 0
    if list_type == "weight":
        valid_upper = 255
    for threshold_key, threshold_value in thresholds.items():
        if threshold_value is not None and threshold_value not in range(valid_lower, valid_upper):
            mso.fail_json(
                msg="Invalid value provided for threshold_{0}: {1}; it must be in the range {2} - {3}".format(
                    threshold_key, threshold_value, valid_lower, valid_upper
                )
            )

    ops = []
    match = None

    # The object dictionary is used as a cache store for schema & template data.
    # This is done to limit the amount of API calls when UUID is not specified for member scope references.
    obj_cache = {}

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")
    obj_cache["template-tenant-{0}".format(template)] = mso_template

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
            "type": list_type,
            "{0}Up".format(list_type): thresholds["up"],
            "{0}Down".format(list_type): thresholds["down"],
        }
        if members is not None:
            mso_values["trackListMembers"] = format_track_list_members(mso, mso_template, members, obj_cache)
        if match:
            append_update_ops_data(ops, match.details, "{0}/{1}".format(path, match.index), mso_values)
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


def format_track_list_members(mso, mso_template, members, obj_cache):
    track_list_members = []

    def get_scope_obj_uuid(scope_type, uuid, obj):
        if uuid:
            return uuid

        name = obj.get("name")
        template = obj.get("template")

        if scope_type == "bd":
            schema_name = obj.get("schema")
            if not schema_name:
                mso.fail_json(msg="A member scope_type is bd and scope is used but the schema option is missing.")
            key = "schema-{0}-{1}-{2}".format(scope_type, schema_name, template)
            mso_schema = obj_cache.get(key)
            if not mso_schema:
                mso_schema = MSOSchema(mso, schema_name, template)
                obj_cache[key] = mso_schema
            mso_schema.set_template(template, fail_module=True)
            mso_schema.set_template_bd(name, fail_module=True)
            return mso_schema.schema_objects.get("template_bd").details.get("uuid")

        if scope_type == "l3out":
            key = "template-{0}-{1}".format(scope_type, template)
            mso_template = obj_cache.get(key)
            if not mso_template:
                mso_template = MSOTemplate(mso, scope_type, template)
                mso_template.validate_template(scope_type)
                obj_cache[key] = mso_template
            return mso_template.get_l3out_object(name=name, fail_module=True).details.get("uuid")

    for member in members:
        scope_type = member.get("scope_type")
        track_member = {
            "trackMember": {
                "destIP": member.get("destination_ip"),
                "scope": get_scope_obj_uuid(scope_type, member.get("scope_uuid"), member.get("scope")),
                "scopeType": scope_type,
                "ipslaMonitoringRef": mso_template.get_ipsla_monitoring_policy(
                    member.get("ipsla_monitoring_policy_uuid"),
                    member.get("ipsla_monitoring_policy"),
                    fail_module=True,
                ).details.get("uuid"),
            },
            "weight": member.get("weight"),
        }
        track_list_members.append(track_member)
    return track_list_members


if __name__ == "__main__":
    main()
