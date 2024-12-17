#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_ntp_policy
short_description: Manage NTP Policies in Fabric Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage NTP (NTP) Policies in Fabric Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the Fabric Policy template.
    type: str
    aliases: [ fabric_policy_template ]
    required: true
  name:
    description:
    - The name of the NTP Policy.
    type: str
    aliases: [ ntp_policy ]
  uuid:
    description:
    - The UUID of the NTP Policy.
    - This parameter is required when the NTP Policy O(name) needs to be updated.
    aliases: [ ntp_policy_uuid ]
    type: str
  description:
    description:
    - The description of the NTP Policy.
    - Providing an empty string will remove the O(description="") from the NTP Policy.
    type: str
  ntp_keys:
    description:
    - The List of NTP client authentication keys.
    - Providing a new list of O(ntp_keys) will completely replace an existing one from the NTP Policy.
    - Providing an empty list will remove the  O(ntp_keys=[]) from the NTP Policy.
    type: list
    elements: dict
    suboptions:
      id:
        description:
        - The key's ID.
        type: int
        aliases: [ key_id ]
      key:
        description:
        - The key.
        type: str
      authentification_type:
        description:
        - the type of authentification.
        type: str
        choices: [ md5, sha1 ]
      trusted:
        description:
        - Set the NTP client authentification key to trusted.
        type: bool
  ntp_providers:
    description:
    - The list of NTP providers.
    - Providing a new list of O(ntp_providers) will completely replace an existing one from the NTP Policy.
    - Providing an empty list will remove the O(ntp_providers=[]) from the NTP Policy.
    type: list
    elements: dict
    suboptions:
      host:
        description:
        - The Hostname or IP address of the NTP provider.
        type: str
      minimum_poll_interval:
        description:
        - The Minimum Polling interval value.
        type: int
        aliases: [ min_poll ]
      maximum_poll_interval:
        description:
        - The Maximum Polling interval value.
        type: int
        aliases: [ max_poll ]
      management_epg_type:
        description:
        - The type of the management EPG.
        type: str
        choices: [ inb, oob ]
        aliases: [ epg_type ]
      management_epg:
        description:
        - The management EPG.
        type: str
        aliases: [ epg ]
      preferred:
        description:
        - Set the NTP provider to preferred.
        type: bool
      authentification_key_id:
        description:
        - The NTP authentification key ID.
        type: int
        aliases: [ key_id ]
  admin_state:
    description:
    - Enable admin state.
    type: str
    choices: [ enabled, disabled ]
  server_state:
    description:
    - Enable server state.
    type: str
    choices: [ enabled, disabled ]
  master_mode:
    description:
    - Enable master mode.
    type: str
    choices: [ enabled, disabled ]
  stratum:
    description:
    - The numerical value of the stratum.
    type: int
  authentification_state:
    description:
    - Enable authentification state.
    type: str
    choices: [ enabled, disabled ]
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
  Use M(cisco.mso.ndo_template) to create the Fabric Policy template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new NTP Policy object
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    name: ntp_policy_1
    ntp_keys:
      - id: 1
        key: my_key
        authentification_type: md5
        trusted: true
    ntp_providers:
      - host: background
        minimum_poll_interval: 4
        maximum_poll_interval: 16
        management_epg_type: oob
        management_epg: default
        preferred: true
        authentification_key_id: 1
    admin_state: enabled
    server_state: enabled
    master_mode: enabled
    stratum: 4
    authentification_state: enabled
    state: present
  register: ntp_policy_1

- name: Update a NTP Policy object name with UUID
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    name: ntp_policy_2
    uuid: "{{ ntp_policy_1.current.uuid }}"
    state: present

- name: Query a NTP Policy object with name
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    name: ntp_policy_2
    state: query
  register: query_name

- name: Query a NTP Policy object with UUID
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    uuid: "{{ ntp_policy_1.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all NTP Policy objects in a Fabric Policy Template
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    state: query
  register: query_all

- name: Delete a NTP Policy object with name
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    name: ntp_policy_2
    state: absent

- name: Delete a NTP Policy object with UUID
  cisco.mso.ndo_ntp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_policy_template
    uuid: "{{ ntp_policy_1.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["fabric_policy_template"]),
        name=dict(type="str", aliases=["ntp_policy"]),
        uuid=dict(type="str", aliases=["ntp_policy_uuid"]),
        description=dict(type="str"),
        ntp_keys=dict(
            type="list",
            elements="dict",
            options=dict(
                id=dict(type="int", aliases=["key_id"]),
                key=dict(type="str", no_log=True),
                authentification_type=dict(type="str", choices=["md5", "sha1"]),
                trusted=dict(type="bool"),
            ),
            no_log=False,
        ),
        ntp_providers=dict(
            type="list",
            elements="dict",
            options=dict(
                host=dict(type="str"),
                minimum_poll_interval=dict(type="int", aliases=["min_poll"]),
                maximum_poll_interval=dict(type="int", aliases=["max_poll"]),
                management_epg_type=dict(type="str", choices=["inb", "oob"], aliases=["epg_type"]),
                management_epg=dict(type="str", aliases=["epg"]),
                preferred=dict(type="bool"),
                authentification_key_id=dict(type="int", aliases=["key_id"]),
            ),
        ),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        server_state=dict(type="str", choices=["enabled", "disabled"]),
        master_mode=dict(type="str", choices=["enabled", "disabled"]),
        stratum=dict(type="int"),
        authentification_state=dict(type="str", choices=["enabled", "disabled"]),
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
    ntp_keys = module.params.get("ntp_keys")
    if ntp_keys:
        ntp_keys = [
            {
                "id": item.get("id"),
                "key": item.get("key"),
                "authType": item.get("authentification_type"),
                "trusted": item.get("trusted"),
            }
            for item in ntp_keys
        ]
    ntp_providers = module.params.get("ntp_providers")
    if ntp_providers:
        ntp_providers = [
            {
                "host": item.get("host"),
                "minPollInterval": item.get("minimum_poll_interval"),
                "maxPollInterval": item.get("maximum_poll_interval"),
                "mgmtEpgType": item.get("management_epg_type"),
                "mgmtEpgName": item.get("management_epg"),
                "preferred": item.get("preferred"),
                "authKeyID": item.get("authentification_key_id"),
            }
            for item in ntp_providers
        ]
    admin_state = module.params.get("admin_state")
    server_state = module.params.get("server_state")
    master_mode = module.params.get("master_mode")
    stratum = module.params.get("stratum")
    authentification_state = module.params.get("authentification_state")
    state = module.params.get("state")

    template_object = MSOTemplate(mso, "tenant", template)
    template_object.validate_template("tenantPolicy")

    ntp_policies = template_object.template.get("fabricPolicyTemplate", {}).get("template", {}).get("ntpPolicies", [])
    object_description = "NTP Policy"

    if state in ["query", "absent"] and ntp_policies == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = ntp_policies
    elif ntp_policies and (name or uuid):
        match = template_object.get_object_by_key_value_pairs(object_description, ntp_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            ntp_policy_attrs_path = "/fabricPolicyTemplate/template/ntpPolicies/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = dict(
            name=name,
            description=description,
            ntpKeys=ntp_keys,
            ntpProviders=ntp_providers,
            adminState=admin_state,
            serverState=server_state,
            masterMode=master_mode,
            stratum=stratum,
            authState=authentification_state,
        )

        if mso.existing:
            append_update_ops_data(ops, match.details, ntp_policy_attrs_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="/fabricPolicyTemplate/template/ntpPolicies/-", value=mso.sent))

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=ntp_policy_attrs_path))

    if not module.check_mode and ops:
        response_object = mso.request(template_object.template_path, method="PATCH", data=ops)
        ntp_policies = response_object.get("fabricPolicyTemplate", {}).get("template", {}).get("ntpPolicies", [])
        match = template_object.get_object_by_key_value_pairs(object_description, ntp_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
