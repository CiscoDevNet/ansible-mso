#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

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
module: ndo_qos_class_policy
short_description: Manage QoS Class Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Quality of Service (QoS) Class Policies.
- This module can be used on Cisco Nexus Dashboard Orchestrator (NDO).
- There can only be a single QoS Class policy in a fabric policy template.
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the fabric policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the QoS Class Policy.
    type: str
    aliases: [ qos_class_policy ]
  uuid:
    description:
    - The UUID of the QoS Class Policy.
    type: str
    aliases: [ qos_class_policy_uuid ]
  description:
    description:
    - The description of the QoS Class Policy.
    type: str
  preserve_cos:
    description:
    - Whether to preserve the Class of Service (CoS).
    type: bool
  qos_levels:
    description:
    - The list of configurable QoS levels for the QoS Class Policy.
    type: list
    elements: dict
    suboptions:
      level:
        description:
        - The QoS level.
        type: str
        choices: [ level1, level2, level3, level4, level5, level6 ]
        required: true
      mtu:
        description:
        - The MTU value.
        - The value must be between 1500 and 9216.
        type: int
        required: true
      minimum_buffer:
        description:
        - The minimum number of reserved buffers.
        - The value must be between 0 and 3.
        type: int
        required: true
      congestion_algorithm:
        description:
        - The congestion algorithm used for this QoS Level.
        type: str
        choices: [ tail_drop, wred ]
        required: true
      wred_configuration:
        description:
        - The Weighted Random Early Detection (WRED) Algorithm configuration.
        - This attribute must be specified when O(qos_levels.congestion_algorithm="wred").
        - Providing an empty list will remove the O(qos_levels.wred_configuration=[])
          from the QoS Class Policy.
        type: dict
        suboptions:
          congestion_notification:
            description:
            - The state of Explicit Congestion Notification (ECN) setting.
            - Enabling Congestion Notification causes the packets that would be dropped to be ECN-marked instead.
            - The default value is C(disabled).
            type: str
            choices: [ enabled, disabled ]
            default: disabled
          forward_non_ecn_traffic:
            description:
            - Whether to forward Non-ECN Traffic.
            - This attribute should only be used when O(qos_levels.wred_configuration.congestion_notification="enabled").
            type: bool
          minimum_threshold:
            description:
            - The The minimum queue threshold as a percentage of the maximum queue length for WRED algorithm.
            - The value must be between 0 and 100.
            type: int
            required: true
          maximum_threshold:
            description:
            - The maximum queue threshold as a percentage of the maximum queue length for WRED algorithm.
            - The value must be between 0 and 100.
            type: int
            required: true
          probability:
            description:
            - The probability value for WRED algorithm.
            - The probability used to determine whether a packet is dropped or queued
              when the average queue size is between the minimum and the maximum threshold values.
            - The value must be between 0 and 100.
            type: int
            required: true
          weight:
            description:
            - The weight value for WRED algorithm.
            - Lower weight prioritizes current queue length, while higher weight prioritizes older queue lengths.
            - The value must be between 0 and 7.
            type: int
            required: true
      scheduling_algorithm:
        description:
        - The QoS Scheduling Algorithm.
        type: str
        choices: [ weighted_round_robin, strict_priority ]
        required: true
      bandwidth_allocated:
        description:
        - The percentage of total bandwidth allocated to this QoS Level.
        - This attribute must be specified when O(qos_levels.scheduling_algorithm="weighted_round_robin").
        - The value must be between 0 and 100.
        type: int
      pfc_admin_state:
        description:
        - The administrative state of the Priority Flow Control (PFC) policy.
        type: str
        choices: [ enabled, disabled ]
        default: disabled
      admin_state:
        description:
        - The policy administrative state.
        type: str
        choices: [ enabled, disabled ]
        default: enabled
      no_drop_cos:
        description:
        - The Class of Service (CoS) level for which to enforce the no drop packet handling even in case of traffic congestion.
        - This attribute must be specified when O(qos_levels.pfc_admin_state="enabled").
        type: str
        choices: [ cos0, cos1, cos2, cos3, cos4, cos5, cos6, cos7, unspecified ]
        default: unspecified
      pfc_scope:
        description:
        - The PFC scope.
        type: str
        choices: [ fabric_wide, intra_tor ]
        default: fabric_wide
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
  The M(cisco.mso.ndo_template) module can be used for this.
- Attempts to create any additional QoS Class policies will only update the existing
  object in the Fabric Policy template.
seealso:
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new QoS Class policy with minimum configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: present
  register: create_qos_class_policy

- name: Update a QoS Class policy with full configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
        mtu: 9000
        minimum_buffer: 1
        congestion_algorithm: wred
        wred_configuration:
          congestion_notification: enabled
          forward_non_ecn_traffic: false
          minimum_threshold: 5
          maximum_threshold: 95
          probability: 80
          weight: 1
        scheduling_algorithm: weighted_round_robin
        bandwidth_allocated: 50
        pfc_admin_state: enabled
        admin_state: enabled
        no_drop_cos: cos1
        pfc_scope: intra_tor
    state: present
  register: update_qos_class_policy

- name: Update a QoS Class policy by adding QoS level2 with minimum configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
        mtu: 9000
        minimum_buffer: 1
        congestion_algorithm: wred
        wred_configuration:
          congestion_notification: enabled
          forward_non_ecn_traffic: false
          minimum_threshold: 5
          maximum_threshold: 95
          probability: 80
          weight: 1
        scheduling_algorithm: weighted_round_robin
        bandwidth_allocated: 50
        pfc_admin_state: enabled
        admin_state: enabled
        no_drop_cos: cos1
        pfc_scope: intra_tor
      - level: level2
        mtu: 9216
        minimum_buffer: 0
        congestion_algorithm: tail_drop
        scheduling_algorithm: strict_priority
    state: present
  register: add_qos_class_policy_level2

- name: Update a QoS Class policy by removing QoS level2
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
        mtu: 9000
        minimum_buffer: 1
        congestion_algorithm: wred
        wred_configuration:
          congestion_notification: enabled
          forward_non_ecn_traffic: false
          minimum_threshold: 5
          maximum_threshold: 95
          probability: 80
          weight: 1
        scheduling_algorithm: weighted_round_robin
        bandwidth_allocated: 50
        pfc_admin_state: enabled
        admin_state: enabled
        no_drop_cos: cos1
        pfc_scope: intra_tor
    state: present
  register: remove_qos_class_policy_level2

- name: Update a QoS Class policy by removing all QoS levels
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels: []
    state: present
  register: remove_qos_class_policy_all_levels

- name: Query QoS Class policy with name
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: query
  register: query_one

- name: Query QoS Class policy with uuid
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ create_qos_class_policy.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Delete a QoS Class policy with name
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: absent

- name: Delete a QoS Class policy with uuid
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_one.current.uuid }}"
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
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    QOS_CONGESTION_ALGORITHM_MAP,
    QOS_SCHEDULING_ALGORITHM_MAP,
    QOS_PFC_SCOPE_MAP,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["qos_class_policy"]),
        description=dict(type="str"),
        uuid=dict(type="str", aliases=["qos_class_policy_uuid"]),
        preserve_cos=dict(type="bool"),
        qos_levels=dict(
            type="list",
            elements="dict",
            options=dict(
                level=dict(type="str", required=True, choices=["level1", "level2", "level3", "level4", "level5", "level6"]),
                mtu=dict(type="int", required=True),
                minimum_buffer=dict(type="int", required=True),
                congestion_algorithm=dict(type="str", choices=["tail_drop", "wred"], required=True),
                wred_configuration=dict(
                    type="dict",
                    options=dict(
                        congestion_notification=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
                        forward_non_ecn_traffic=dict(type="bool"),
                        minimum_threshold=dict(type="int", required=True),
                        maximum_threshold=dict(type="int", required=True),
                        probability=dict(type="int", required=True),
                        weight=dict(type="int", required=True),
                    ),
                ),
                scheduling_algorithm=dict(type="str", choices=["weighted_round_robin", "strict_priority"], required=True),
                bandwidth_allocated=dict(type="int"),
                pfc_admin_state=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
                admin_state=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
                no_drop_cos=dict(type="str", choices=["cos0", "cos1", "cos2", "cos3", "cos4", "cos5", "cos6", "cos7", "unspecified"], default="unspecified"),
                pfc_scope=dict(type="str", choices=["fabric_wide", "intra_tor"], default="fabric_wide"),
            ),
            required_if=[
                ["congestion_algorithm", "wred", ["wred_configuration"]],
                ["scheduling_algorithm", "weighted_round_robin", ["bandwidth_allocated"]],
                ["pfc_admin_state", "enabled", ["no_drop_cos"]],
            ],
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
        required_one_of=[
            ["template", "template_id"],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    description = module.params.get("description")
    uuid = module.params.get("uuid")
    preserve_cos = module.params.get("preserve_cos")
    qos_levels = module.params.get("qos_levels")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template, template_id)
    mso_template.validate_template("fabricPolicy")
    object_description = "QoS Class Policy"

    path = "/fabricPolicyTemplate/template/qosClass"
    existing_qos_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("qosClass", {})
    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [existing_qos_policies],
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(mso_template.update_config_with_template_and_references(match.details))
    else:
        mso.existing = mso.previous = mso_template.update_config_with_template_and_references(existing_qos_policies)

    if state == "present":
        mso_values = {
            "name": name,
            "description": description,
            "preserveCos": preserve_cos,
        }
        qos_levels, remove_data = format_qos_levels(mso, qos_levels)
        if isinstance(qos_levels, dict):
            mso_values.update(qos_levels)
        if match:
            append_update_ops_data(ops, match.details, path, mso_values, remove_data)
            mso.sanitize(match.details, collate=True)

        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        qos_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("qosClass", {})
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [qos_policies],
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = mso_template.update_config_with_template_and_references(match.details)
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso_template.update_config_with_template_and_references(mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def format_qos_levels(mso, qos_levels=None):
    remove_data = []
    if isinstance(qos_levels, list):
        exsting_qos_levels = set()
        for qos_level in qos_levels:
            level = qos_level.get("level")
            if level in exsting_qos_levels:
                mso.fail_json(msg="Duplicate configurations for QoS {0}".format(level))
            else:
                exsting_qos_levels.add(level)
        remove_data = list({"level1", "level2", "level3", "level4", "level5", "level6"}.difference(exsting_qos_levels))

        formatted_qos_levels = {
            qos_level.get("level"): {
                "adminState": qos_level.get("admin_state"),
                "minBuffer": qos_level.get("minimum_buffer"),
                "mtu": qos_level.get("mtu"),
                "congestionAlgorithm": QOS_CONGESTION_ALGORITHM_MAP.get(qos_level.get("congestion_algorithm")),
                "wredConfig": (
                    {
                        "congestionNotification": qos_level["wred_configuration"].get("congestion_notification"),
                        "minThreshold": qos_level["wred_configuration"].get("minimum_threshold"),
                        "maxThreshold": qos_level["wred_configuration"].get("maximum_threshold"),
                        "probability": qos_level["wred_configuration"].get("probability"),
                        "weight": qos_level["wred_configuration"].get("weight"),
                        "forwardNonEcn": qos_level["wred_configuration"].get("forward_non_ecn_traffic"),
                    }
                    if qos_level.get("wred_configuration")
                    else None
                ),
                "schedulingAlgorithm": QOS_SCHEDULING_ALGORITHM_MAP.get(qos_level.get("scheduling_algorithm")),
                "bandwidthAllocated": qos_level.get("bandwidth_allocated"),
                "pfcAdminState": qos_level.get("pfc_admin_state"),
                "noDropCoS": qos_level.get("no_drop_cos"),
                "pfcScope": QOS_PFC_SCOPE_MAP.get(qos_level.get("pfc_scope")),
            }
            for qos_level in qos_levels
        }
        mso.sanitize(formatted_qos_levels)
        return formatted_qos_levels, remove_data
    else:
        return None, remove_data


if __name__ == "__main__":
    main()
