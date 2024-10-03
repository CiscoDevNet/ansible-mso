#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_mac_sec_policy
short_description: Manage MACSec Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage MACSec Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  mac_sec_policy:
    description:
    - The name of the MACSec Policy.
    type: str
    aliases: [ name ]
  mac_sec_policy_uuid:
    description:
    - The uuid of the MACSec Policy.
    - This parameter is required when the O(mac_sec_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the MACSec Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the MACSec Policy. (Enables or disables the policy)
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  interface_type:
    description:
    - The type of the interfaces this policy will be applied to.
    type: str
    choices: [ fabric, access ]
    default: fabric
  cipher_suite:
    description:
    - The cipher suite to be used for encryption.
    - The default value is C(256_gcm_aes_xpn).
    type: str
    choices: [ 128_gcm_aes, 128_gcm_aes_xpn, 256_gcm_aes, 256_gcm_aes_xpn ]
  window_size:
    description:
    - The window size defines the maximum number of frames that can be received out of order
    - before a replay attack is detected.
    - The value must be between 0 and 4294967295.
    - The default value is 0 for type C(fabric) and 64 for type C(access).
    type: int
  security_policy:
    description:
    - The security policy to allow trafic on the link for the MACSec Policy.
    - The default value is C(should_secure).
    type: str
    choices: [ should_secure, must_secure ]
  sak_expiry_time:
    description:
    - The expiry time for the Security Association Key (SAK) for the MACSec Policy.
    - The value must be 0 or between 60 and 2592000.
    - The default value is 0.
    type: int
  confidentiality_offset:
    description:
    - The confidentiality offset for the MACSec Policy.
    - The default value is 0.
    - This parameter is only available for type C(access).
    type: int
    choices: [ 0, 30, 50 ]
  key_server_priority:
    description:
    - The key server priority for the MACSec Policy.
    - The value must be between 0 and 255.
    - The default value 16 for type C(access).
    - This parameter is only available for type C(access).
    type: int
  mac_sec_keys:
    description:
    - List of the MACSec Keys.
    - Providing an empty list will remove the O(mac_sec_keys) from the MACSec Policy.
    - The old O(mac_sec_keys) entries will be replaced with the new entries during update.
    type: list
    elements: dict
    suboptions:
      key_name:
        description:
        - The name of the MACSec Key.
        - Key Name has to be Hex chars [0-9a-fA-F]
        type: str
        required: true
      psk:
        description:
        - The Pre-Shared Key (PSK) for the MACSec Key.
        - PSK has to be 64 chars long if cipher suite is C(256_gcm_aes) or C(256_gcm_aes_xpn).
        - PSK has to be 32 chars long if cipher suite is C(128_gcm_aes) or C(128_gcm_aes_xpn).
        - PSK has to be Hex chars [0-9a-fA-F]
        type: str
        required: true
      start_time:
        description:
        - The start time for the MACSec Key.
        - The date time format - YYYY-MM-DD HH:MM:SS or 'now'
        - The start time for each key_name should be unique.
        - The default value is C(now).
        type: str
      end_time:
        description:
        - The end time for the MACSec Key.
        - The date time format - YYYY-MM-DD HH:MM:SS or 'infinite'
        - The default value is C(infinite).
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
- name: Create a new MACSec Policy of interface_type fabric
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy: ansible_test_mac_sec_policy
    description: "Ansible Test MACSec Policy"
    state: present

- name: Create a new MACSec Policy of interface_type access
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy: ansible_test_mac_sec_policy
    description: "Ansible Test MACSec Policy"
    mac_sec_keys:
      - key_name: ansible_test_key
        psk: 'AA111111111111111111111111111111111111111111111111111111111111aa'
        start_time: '2029-12-11 11:12:13'
        end_time: 'infinite'
    state: present

- name: Query a MACSec Policy with mac_sec_policy name
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy: ansible_test_mac_sec_policy
    state: query
  register: query_one

- name: Query all MACSec Policies
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    state: query
  register: query_all

- name: Query a MACSec Policy with mac_sec_policy UUID
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy_uuid: ansible_test_mac_sec_policy_uuid
    state: query
  register: query_uuid

- name: Delete a MACSec Policy with name
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy: ansible_test_mac_sec_policy
    state: absent

- name: Delete a MACSec Policy with UUID
  cisco.mso.ndo_mac_sec_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    mac_sec_policy_uuid: ansible_test_mac_sec_policy_uuid
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import NDO_CIPHER_SUITE_MAP, NDO_SECURITY_POLICY_MAP
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            mac_sec_policy=dict(type="str", aliases=["name"]),
            mac_sec_policy_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            admin_state=dict(type="str", choices=["enabled", "disabled"]),
            interface_type=dict(type="str", choices=["fabric", "access"], default="fabric"),
            cipher_suite=dict(type="str", choices=list(NDO_CIPHER_SUITE_MAP)),
            window_size=dict(type="int"),
            security_policy=dict(type="str", choices=list(NDO_SECURITY_POLICY_MAP)),
            sak_expiry_time=dict(type="int"),
            confidentiality_offset=dict(type="int", choices=[0, 30, 50]),
            key_server_priority=dict(type="int"),
            mac_sec_keys=dict(
                type="list",
                elements="dict",
                options=dict(
                    key_name=dict(type="str", required=True),
                    psk=dict(type="str", required=True, no_log=True),
                    start_time=dict(type="str"),
                    end_time=dict(type="str"),
                ),
                no_log=False,
            ),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["mac_sec_policy", "mac_sec_policy_uuid"], True],
            ["state", "absent", ["mac_sec_policy", "mac_sec_policy_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    mac_sec_policy = module.params.get("mac_sec_policy")
    mac_sec_policy_uuid = module.params.get("mac_sec_policy_uuid")
    description = module.params.get("description")
    admin_state = module.params.get("admin_state")
    interface_type = module.params.get("interface_type")
    cipher_suite = NDO_CIPHER_SUITE_MAP.get(module.params.get("cipher_suite"))
    window_size = module.params.get("window_size")
    security_policy = NDO_SECURITY_POLICY_MAP.get(module.params.get("security_policy"))
    sak_expiry_time = module.params.get("sak_expiry_time")
    confidentiality_offset = module.params.get("confidentiality_offset")
    key_server_priority = module.params.get("key_server_priority")
    mac_sec_keys = module.params.get("mac_sec_keys")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/macsecPolicies"
    object_description = "MACSec Policy"

    existing_mac_sec_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
    if mac_sec_policy or mac_sec_policy_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_mac_sec_policies,
            [KVPair("uuid", mac_sec_policy_uuid) if mac_sec_policy_uuid else KVPair("name", mac_sec_policy)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_mac_sec_policies

    if state == "present":

        if match:

            if mac_sec_policy and match.details.get("name") != mac_sec_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=mac_sec_policy))
                match.details["name"] = mac_sec_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if admin_state and match.details.get("adminState") != admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/adminState".format(path, match.index), value=admin_state))
                match.details["adminState"] = admin_state

            if interface_type and match.details.get("type") != interface_type:
                mso.fail_json(msg="Type cannot be changed for an existing MACSec Policy.")

            if cipher_suite and match.details.get("macsecParams")["cipherSuite"] != cipher_suite:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/cipherSuite".format(path, match.index), value=cipher_suite))
                match.details["macsecParams"]["cipherSuite"] = cipher_suite

            if window_size and match.details.get("macsecParams")["windowSize"] != window_size:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/windowSize".format(path, match.index), value=window_size))
                match.details["macsecParams"]["windowSize"] = window_size

            if security_policy and match.details.get("macsecParams")["securityPol"] != security_policy:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/securityPol".format(path, match.index), value=security_policy))
                match.details["macsecParams"]["securityPol"] = security_policy

            if sak_expiry_time and match.details.get("macsecParams")["sakExpiryTime"] != sak_expiry_time:
                ops.append(dict(op="replace", path="{0}/{1}/macsecParams/sakExpiryTime".format(path, match.index), value=sak_expiry_time))
                match.details["macsecParams"]["sakExpiryTime"] = sak_expiry_time

            if interface_type == "access":
                if confidentiality_offset and match.details.get("macsecParams")["confOffSet"] != confidentiality_offset:
                    ops.append(
                        dict(op="replace", path="{0}/{1}/macsecParams/confOffSet".format(path, match.index), value="offset{0}".format(confidentiality_offset))
                    )
                    match.details["macsecParams"]["confOffSet"] = "offset{0}".format(confidentiality_offset)

                if key_server_priority and match.details.get("macsecParams")["keyServerPrio"] != key_server_priority:
                    ops.append(dict(op="replace", path="{0}/{1}/macsecParams/keyServerPrio".format(path, match.index), value=key_server_priority))
                    match.details["macsecParams"]["keyServerPrio"] = key_server_priority

            if mac_sec_keys:
                # updating mac_sec_keys modifies the existing list with the new list
                mac_sec_keys_list = []
                for mac_sec_key in mac_sec_keys:
                    mac_sec_keys_list.append(
                        dict(
                            keyname=mac_sec_key.get("key_name"),
                            psk=mac_sec_key.get("psk"),
                            start=mso.verify_time_format(mac_sec_key.get("start_time")) if mac_sec_key.get("start_time") else None,
                            end=mso.verify_time_format(mac_sec_key.get("end_time")) if mac_sec_key.get("end_time") else None,
                        )
                    )

                if mac_sec_keys_list != match.details.get("macsecKeys", []):
                    ops.append(dict(op="replace", path="{0}/{1}/macsecKeys".format(path, match.index), value=mac_sec_keys_list))
                match.details["macsecKeys"] = mac_sec_keys
            elif mac_sec_keys == []:
                # remove mac_sec_keys if the list is empty
                ops.append(dict(op="remove", path="{0}/{1}/macsecKeys".format(path, match.index)))
                match.details.pop("macsecKeys", None)

            mso.sanitize(match.details)

        else:
            mac_sec_param_map = {}

            payload = {"name": mac_sec_policy, "templateId": mso_template.template.get("templateId"), "schemaId": mso_template.template.get("schemaId")}
            payload["type"] = interface_type

            if description:
                payload["description"] = description
            if admin_state:
                payload["adminState"] = admin_state
            if cipher_suite:
                mac_sec_param_map["cipherSuite"] = cipher_suite
            if window_size:
                mac_sec_param_map["windowSize"] = window_size
            if security_policy:
                mac_sec_param_map["securityPol"] = security_policy
            if sak_expiry_time:
                mac_sec_param_map["sakExpiryTime"] = sak_expiry_time

            if interface_type == "access":
                if confidentiality_offset:
                    mac_sec_param_map["confOffSet"] = "offset{0}".format(confidentiality_offset)
                if key_server_priority:
                    mac_sec_param_map["keyServerPrio"] = key_server_priority
                payload["macsecParams"] = mac_sec_param_map

            mac_sec_keys_list = []
            if mac_sec_keys:
                for mac_sec_key in mac_sec_keys:
                    mac_sec_key_dict = {
                        "keyname": mac_sec_key.get("key_name"),
                        "psk": mac_sec_key.get("psk"),
                    }
                    if mac_sec_key.get("start_time"):
                        mac_sec_key_dict["start"] = mac_sec_key.get("start_time")
                    if mac_sec_key.get("end_time"):
                        mac_sec_key_dict["end"] = mac_sec_key.get("end_time")
                    mac_sec_keys_list.append(mac_sec_key_dict)
                payload["macsecKeys"] = mac_sec_keys_list

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        macsec_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            macsec_policies,
            [KVPair("uuid", mac_sec_policy_uuid) if mac_sec_policy_uuid else KVPair("name", mac_sec_policy)],
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
