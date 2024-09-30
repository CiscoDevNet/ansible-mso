#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_interface_setting
short_description: Manage Interface Policy Groups on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Interface Policy Groups on Cisco Nexus Dashboard Orchestrator (NDO).
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
  interface_policy_group:
    description:
    - The name of the interface policy group.
    type: str
    aliases: [ name ]
  interface_policy_group_uuid:
    description:
    - The UUID of the interface policy group.
    - This parameter is required when the O(interface_policy_group) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the interface policy group.
    type: str
  interface_type:
    description:
    - The type of the interface policy group.
    - The default value is C(physical).
    type: str
    choices: [ physical, pc_vpc ]
  speed:
    description:
    - The data transfer rate for the port in interface policy group.
    - The default value is C(inherit).
    type: str
    choices: [ 100M, 1G, 10G, 25G, 40G, 50G, 100G, 200G, 400G, inherit ]
  auto_negotiation:
    description:
    - The auto negotiation of the port in interface policy group.
    - The default value is C(on).
    type: str
    choices: [ 'on', 'off', on_enforce ]
  vlan_scope:
    description:
    - The VLAN VLAN encapsulation value to map to EPG.
    - The default value is C(local).
    type: str
    choices: [ local, global, port_local ]
  cdp_admin_state:
    description:
    - The CDP admin state enables Cisco Discovery Protocol (CDP) on the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  lldp:
    description:
    - The LLDP enables Link Layer Discovery Protocol (LLDP) on the interface.
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  domains:
    description:
    - The domains with which you want to associate this interface policy.
    type: list
    elements: str
  port_channel_mode:
    description:
    - The port channel mode of the interface policy group.
    - The default value is C(static_channel_mode_on).
    - The value is available only when the interface_type is C(pc_vpc).
    type: str
    choices: [ static_channel_mode_on, lacp_passive, lacp_active,  mac_pinning, mac_pinning_physical_nic_load, use_explicit_failover_order ]
  min_links:
    description:
    - The minimum links of the interface policy group.
    - The default value is 1.
    - The value must be between 1 and 16.
    - The value is available only when the interface_type is C(pc_vpc).
    type: int
  max_links:
    description:
    - The maximum links of the interface policy group.
    - The default value is 16.
    - The value must be between 1 and 64.
    - The value is available only when the interface_type is C(pc_vpc).
    type: int
  control:
    description:
    - The control of the interface policy group.
    - The default value is C(fast_sel_hot_stdby), C(graceful_conv), C(susp_individual).
    - The value is available only when the interface_type is C(pc_vpc).
    type: list
    elements: str
    choices: [ fast_sel_hot_stdby, graceful_conv, susp_individual, load_defer, symmetric_hash ]
  load_balance_hashing:
    description:
    - The load balance hashing of the interface policy group.
    - The value is available only when the interface_type is C(pc_vpc).
    type: str
    choices: [ destination_ip, layer_4_destination_ip, layer_4_source_ip, source_ip ]
  sync_e:
    description:
    - The syncE policy assigned to the interface policy group.
    type: str
  link_level_debounce_interval:
    description:
    - The debounce interval of the link level.
    - The default value is 100.
    - The value must be an integer between 0 and 5000.
    type: int
  link_level_bring_up_delay:
    description:
    - The time in milliseconds that the decision feedback equalizer (DFE) tuning is delayed when a port is coming up.
    - The default value is 0.
    - The value must be an integer between 0 and 10000.
    type: int
  link_level_fec:
    description:
    - The Forwarding Error Correction (FEC) is used for obtaining error control in data transmission.
    - The default value is C(inherit).
    type: str
    choices: [ inherit, cl74_fc_fec, cl91_rs_fec, cons16_rs_fec, ieee_rs_fec, kp_fec, disable_fec ]
  l2_interface_qin_q:
    description:
    - The QinQ enables  mapping double-tagged VLAN traffic.
    - The default value is C(disabled).
    type: str
    choices: [ core_port, double_q_tag_port, edge_port, disabled ]
  l2_interface_reflective_relay:
    description:
    - The reflective relay enabled forwarding trafic.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  lldp_transmit_state:
    description:
    - The LLDP transmit state allows Link Layer Discovery Protocol (LLDP) packets to be sent from the interface.
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  lldp_receive_state:
    description:
    - The LLDP receive state allows LLDP packets to be received by the interface.
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  stp_bpdu_filter:
    description:
    - The STP Bridge Protocol Data Unit (BPDU) filter filters out any BPDUs on the port.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  stp_bpdu_guard:
    description:
    - The STP BPDU guard prevents the port from receiving BPDUs.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_transmit_state:
    description:
    - The LLFC transmit state alows Link Level Flow Control (LLFC) packets to be sent from the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_receive_state:
    description:
    - The LLFC receive state allows LLFC packets to be received by the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  mcp_admin_state:
    description:
    - The MCP admin state enables MisCabling Protocol (MCP) on the interface.
    - The default value is C(enabled).
    type: str
    choices: [ enabled, disabled ]
  mcp_strict_mode:
    description:
    - The MCP strict mode.
    - The default value is C(off).
    type: str
    choices: [ 'on', 'off' ]
  mcp_initial_delay_time:
    description:
    - The MCP initial delay time in seconds.
    - The default value is 180.
    - The value must be between 0 and 1800.
    - The value is available only when the mcp_strict_mode is C(on).
    type: int
  mcp_transmission_frequency_sec:
    description:
    - The MCP transmission frequency in seconds.
    - The default value is 2.
    - The value must be between 0 and 300.
    - The value is available only when the mcp_strict_mode is C(on).
    type: int
  mcp_transmission_frequency_msec:
    description:
    - The MCP transmission frequency in milliseconds.
    - The default value is 0.
    - The value must be between 0 and 999.
    - The value is available only when the mcp_strict_mode is C(on).
    type: int
  mcp_grace_period_sec:
    description:
    - The MCP grace period in seconds.
    - The default value is 3.
    - The value must be between 0 and 300.
    - The value is available only when the mcp_strict_mode is C(on).
    type: int
  mcp_grace_period_msec:
    description:
    - The MCP grace period in milliseconds.
    - The default value is 0.
    - The value must be between 0 and 999.
    - The value is available only when the mcp_strict_mode is C(on).
    type: int
  pfc_admin_state:
    description:
    - The PFC admin state.
    - The default value is C(auto).
    type: str
    choices: [ 'on', 'off', auto ]
  access_mac_sec_policy:
    description:
    - The access MACsec policy.
    - The value is available only when the mcp_admin_state is C(enabled).
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
- name: Create an Interface policy group of interface_type physical
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_physical
  description: "Interface Policy Group for Ansible Test"
  interface_type: physical
  state: present

- name: Create an Interface policy group of interface_type pc_vpc
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_pc_vpc
  description: "Interface Policy Group for Ansible Test"
  interface_type: pc_vpc
  state: present

- name: Query all Interface policy groups
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  state: query
  register: query_all

- name: Query a specific Interface policy group with name
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_physical
  state: query
  register: query_one_name

- name: Query a specific Interface policy group with UUID
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group_uuid: ansible_test_interface_policy_group_uuid
  state: query
  register: query_one_uuid

- name: Delete an Interface policy group with name
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_physical
  state: absent

- name: Delete an Interface policy group with UUID
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group_uuid: ansible_test_interface_policy_group_uuid
  state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    PORT_CHANNEL_MODE_MAP,
    CONTROL_MAP,
    LINK_LEVEL_FEC_MAP,
    L2_INTERFACE_QIN_Q_MAP,
    LOAD_BALANCE_HASHING_MAP,
)
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            interface_policy_group=dict(type="str", aliases=["name"]),
            interface_policy_group_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            interface_type=dict(type="str", choices=["physical", "pc_vpc"]),  # pc_vpc = portchannel
            speed=dict(type="str", choices=["100M", "1G", "10G", "25G", "40G", "50G", "100G", "200G", "400G", "inherit"]),
            auto_negotiation=dict(type="str", choices=["on", "off", "on_enforce"]),  # on_enforce = on-enforce
            vlan_scope=dict(type="str", choices=["local", "global", "port_local"]),  # port_local = portlocal
            cdp_admin_state=dict(type="str", choices=["enabled", "disabled"]),
            lldp=dict(type="str", choices=["enabled", "disabled"]),
            domains=dict(type="list", elements="str"),
            port_channel_mode=dict(type="str", choices=list(PORT_CHANNEL_MODE_MAP.keys())),
            min_links=dict(type="int"),
            max_links=dict(type="int"),
            control=dict(type="list", elements="str", choices=list(CONTROL_MAP.keys())),
            load_balance_hashing=dict(type="str", choices=list(LOAD_BALANCE_HASHING_MAP.keys())),
            sync_e=dict(type="str"),
            link_level_debounce_interval=dict(type="int"),
            link_level_bring_up_delay=dict(type="int"),
            link_level_fec=dict(type="str", choices=list(LINK_LEVEL_FEC_MAP.keys())),
            l2_interface_qin_q=dict(type="str", choices=list(L2_INTERFACE_QIN_Q_MAP.keys())),
            l2_interface_reflective_relay=dict(type="str", choices=["enabled", "disabled"]),
            lldp_transmit_state=dict(type="str", choices=["enabled", "disabled"]),
            lldp_receive_state=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_filter=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_guard=dict(type="str", choices=["enabled", "disabled"]),
            llfc_transmit_state=dict(type="str", choices=["enabled", "disabled"]),
            llfc_receive_state=dict(type="str", choices=["enabled", "disabled"]),
            mcp_admin_state=dict(type="str", choices=["enabled", "disabled"]),
            mcp_strict_mode=dict(type="str", choices=["on", "off"]),
            mcp_initial_delay_time=dict(type="int"),
            mcp_transmission_frequency_sec=dict(type="int"),
            mcp_transmission_frequency_msec=dict(type="int"),
            mcp_grace_period_sec=dict(type="int"),
            mcp_grace_period_msec=dict(type="int"),
            pfc_admin_state=dict(type="str", choices=["on", "off", "auto"]),
            access_mac_sec_policy=dict(type="str"),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["interface_policy_group", "interface_type"]],
            ["state", "absent", ["interface_policy_group", "interface_policy_group_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    description = module.params.get("description")
    interface_type = module.params.get("interface_type")  # .replace("_", "")
    if interface_type == "pc_vpc":
        interface_type = "portchannel"
    speed = module.params.get("speed")
    auto_negotiation = module.params.get("auto_negotiation")  # .replace("_", "-")
    if auto_negotiation == "on_enforce":
        auto_negotiation = "on-enforce"
    vlan_scope = module.params.get("vlan_scope")  # .replace("_", "")
    if vlan_scope == "port_local":
        vlan_scope = "portlocal"
    cdp_admin_state = module.params.get("cdp_admin_state")
    lldp = module.params.get("lldp")
    domains = module.params.get("domains")
    port_channel_mode = PORT_CHANNEL_MODE_MAP.get(module.params.get("port_channel_mode"))
    min_links = module.params.get("min_links")
    max_links = module.params.get("max_links")
    control = CONTROL_MAP.get(module.params.get("control"))
    load_balance_hashing = LOAD_BALANCE_HASHING_MAP.get(module.params.get("load_balance_hashing"))
    sync_e = module.params.get("sync_e")
    link_level_debounce_interval = module.params.get("link_level_debounce_interval")
    link_level_bring_up_delay = module.params.get("link_level_bring_up_delay")
    link_level_fec = LINK_LEVEL_FEC_MAP.get(module.params.get("link_level_fec"))
    l2_interface_qin_q = L2_INTERFACE_QIN_Q_MAP.get(module.params.get("l2_interface_qin_q"))
    l2_interface_reflective_relay = module.params.get("l2_interface_reflective_relay")
    lldp_transmit_state = module.params.get("lldp_transmit_state")
    lldp_receive_state = module.params.get("lldp_receive_state")
    stp_bpdu_filter = module.params.get("stp_bpdu_filter")
    stp_bpdu_guard = module.params.get("stp_bpdu_guard")
    llfc_transmit_state = module.params.get("llfc_transmit_state")
    llfc_receive_state = module.params.get("llfc_receive_state")
    mcp_admin_state = module.params.get("mcp_admin_state")
    mcp_strict_mode = module.params.get("mcp_strict_mode")
    mcp_initial_delay_time = module.params.get("mcp_initial_delay_time")
    mcp_transmission_frequency_sec = module.params.get("mcp_transmission_frequency_sec")
    mcp_transmission_frequency_msec = module.params.get("mcp_transmission_frequency_msec")
    mcp_grace_period_sec = module.params.get("mcp_grace_period_sec")
    mcp_grace_period_msec = module.params.get("mcp_grace_period_msec")
    pfc_admin_state = module.params.get("pfc_admin_state")
    access_mac_sec_policy = module.params.get("access_mac_sec_policy")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/interfacePolicyGroups"
    object_description = "Interface Policy Groups"

    template_info = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {})

    existing_interface_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("interfacePolicyGroups", [])
    if interface_policy_group or interface_policy_group_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_interface_policies,
            [KVPair("uuid", interface_policy_group_uuid) if interface_policy_group_uuid else KVPair("name", interface_policy_group)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_interface_policies

    if state == "present":

        if match:
            if interface_policy_group and match.details.get("name") != interface_policy_group:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=interface_policy_group))
                match.details["name"] = interface_policy_group

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if interface_type and match.details.get("type") != interface_type:
                mso.fail_json(msg="Interface type cannot be changed")

            if domains:
                # the existing domain list is updated by the new domain list
                domain_list = []
                # get names and uuids of existing domains
                existing_physical_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("domains", [])}
                existing_l3_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("l3Domains", [])}
                for item in domains:
                    if item in existing_physical_domains:
                        domain_list.append(existing_physical_domains[item])
                    elif item in existing_l3_domains:
                        domain_list.append(existing_l3_domains[item])
                    else:
                        mso.fail_json(msg="Domain '{0}' not found in the template '{1}'".format(item, template))
                ops.append(dict(op="replace", path="{0}/{1}/domains".format(path, match.index), value=domain_list))
                match.details["domains"] = domain_list

            if sync_e:
                existing_sync_e = {sync_e["name"]: sync_e["uuid"] for sync_e in template_info.get("syncEthIntfPolicies", [])}
                if sync_e in existing_sync_e and existing_sync_e[sync_e] != sync_e:
                    ops.append(dict(op="replace", path="{0}/{1}/syncEthPolicy".format(path, match.index), value=existing_sync_e[sync_e]))
                    match.details["syncEthPolicy"] = existing_sync_e[sync_e]
                else:
                    mso.fail_json(msg="SyncE policy '{0}' not found in the template '{1}'".format(sync_e, template))

            if access_mac_sec_policy:
                if mcp_admin_state and (mcp_admin_state == "disabled" or match.details.get("mcp", {}).get("adminState") == "disabled"):
                    mso.fail_json(msg="Access MACsec policy can only be set when mcp_admin_state is enabled")
                else:
                    existing_access_mac_sec_policy = {
                        mac_sec_policy["name"]: mac_sec_policy["uuid"] for mac_sec_policy in template_info.get("macsecPolicies", [])
                    }
                    if access_mac_sec_policy in existing_access_mac_sec_policy and (
                        existing_access_mac_sec_policy[access_mac_sec_policy] != access_mac_sec_policy
                    ):
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/{1}/accessMACsecPolicy".format(path, match.index),
                                value=existing_access_mac_sec_policy[access_mac_sec_policy],
                            )
                        )
                        match.details["accessMACsecPolicy"] = existing_access_mac_sec_policy[access_mac_sec_policy]
                    else:
                        mso.fail_json(msg="Access MACsec policy '{0}' not found in the template '{1}'".format(access_mac_sec_policy, template))

            # dictionaries
            if cdp_admin_state and match.details.get("cdp", {}).get("adminState") != cdp_admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/cdp/adminState".format(path, match.index), value=cdp_admin_state))
                match.details["cdp"]["adminState"] = cdp_admin_state

            if pfc_admin_state and match.details.get("pfc", {}).get("adminState") != pfc_admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/pfc/adminState".format(path, match.index), value=pfc_admin_state))
                match.details["pfc"]["adminState"] = pfc_admin_state

            if llfc_transmit_state and match.details.get("llfc", {}).get("transmitState") != llfc_transmit_state:
                ops.append(dict(op="replace", path="{0}/{1}/llfc/transmitState".format(path, match.index), value=llfc_transmit_state))
                match.details["llfc"]["transmitState"] = llfc_transmit_state

            if llfc_receive_state and match.details.get("llfc", {}).get("receiveState") != llfc_receive_state:
                ops.append(dict(op="replace", path="{0}/{1}/llfc/receiveState".format(path, match.index), value=llfc_receive_state))
                match.details["llfc"]["receiveState"] = llfc_receive_state

            if stp_bpdu_filter and match.details.get("stp", {}).get("bpduFilterEnabled") != stp_bpdu_filter:
                ops.append(dict(op="replace", path="{0}/{1}/stp/bpduFilterEnabled".format(path, match.index), value=stp_bpdu_filter))
                match.details["stp"]["bpduFilterEnabled"] = stp_bpdu_filter

            if stp_bpdu_guard and match.details.get("stp", {}).get("bpduGuardEnabled") != stp_bpdu_guard:
                ops.append(dict(op="replace", path="{0}/{1}/stp/bpduGuardEnabled".format(path, match.index), value=stp_bpdu_guard))
                match.details["stp"]["bpduGuardEnabled"] = stp_bpdu_guard

            if l2_interface_qin_q and match.details.get("l2Interface", {}).get("qinq") != l2_interface_qin_q:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/qinq".format(path, match.index), value=l2_interface_qin_q))
                match.details["l2Interface"]["qinq"] = l2_interface_qin_q

            if l2_interface_reflective_relay and match.details.get("l2Interface", {}).get("reflectiveRelay") != l2_interface_reflective_relay:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/reflectiveRelay".format(path, match.index), value=l2_interface_reflective_relay))
                match.details["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay

            if vlan_scope and match.details.get("l2Interface", {}).get("vlanScope") != vlan_scope:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/vlanScope".format(path, match.index), value=vlan_scope))
                match.details["l2Interface"]["vlanScope"] = vlan_scope

            if lldp:
                if lldp == "disabled":
                    if not (lldp_receive_state == "disabled" and lldp_transmit_state == "disabled"):
                        mso.fail_json(msg="lldp_receive_state and lldp_transmit_state must be 'disabled' when LLDP is disabled")
                if lldp_receive_state and match.details.get("lldp", {}).get("receiveState") != lldp_receive_state:
                    ops.append(dict(op="replace", path="{0}/{1}/lldp/receiveState".format(path, match.index), value=lldp_receive_state))
                    match.details["lldp"]["receiveState"] = lldp_receive_state
                if lldp_transmit_state and match.details.get("lldp", {}).get("transmitState") != lldp_transmit_state:
                    ops.append(dict(op="replace", path="{0}/{1}/lldp/transmitState".format(path, match.index), value=lldp_transmit_state))
                    match.details["lldp"]["transmitState"] = lldp_transmit_state

            if link_level_debounce_interval and match.details.get("linkLevel", {}).get("debounceInterval") != link_level_debounce_interval:
                ops.append(dict(op="replace", path="{0}/{1}/linkLevel/debounceInterval".format(path, match.index), value=link_level_debounce_interval))
                match.details["linkLevel"]["debounceInterval"] = link_level_debounce_interval

            if link_level_bring_up_delay and match.details.get("linkLevel", {}).get("bringUpDelay") != link_level_bring_up_delay:
                ops.append(dict(op="replace", path="{0}/{1}/linkLevel/bringUpDelay".format(path, match.index), value=link_level_bring_up_delay))
                match.details["linkLevel"]["bringUpDelay"] = link_level_bring_up_delay

            if link_level_fec and match.details.get("linkLevel", {}).get("fec") != link_level_fec:
                ops.append(dict(op="replace", path="{0}/{1}/linkLevel/fec".format(path, match.index), value=link_level_fec))
                match.details["linkLevel"]["fec"] = link_level_fec

            if speed and match.details.get("linkLevel", {}).get("speed") != speed:
                ops.append(dict(op="replace", path="{0}/{1}/linkLevel/speed".format(path, match.index), value=speed))
                match.details["linkLevel"]["speed"] = speed

            if auto_negotiation and match.details.get("linkLevel", {}).get("autoNegotiation") != auto_negotiation:
                ops.append(dict(op="replace", path="{0}/{1}/linkLevel/autoNegotiation".format(path, match.index), value=auto_negotiation))
                match.details["linkLevel"]["autoNegotiation"] = auto_negotiation

            if mcp_admin_state and match.details.get("mcp", {}).get("adminState") != mcp_admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/adminState".format(path, match.index), value=mcp_admin_state))
                match.details["mcp"]["adminState"] = mcp_admin_state

            if mcp_strict_mode and match.details.get("mcp", {}).get("mcpMode") != mcp_strict_mode:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/mcpMode".format(path, match.index), value=mcp_strict_mode))
                match.details["mcp"]["mcpMode"] = mcp_strict_mode

            if mcp_initial_delay_time and match.details.get("mcp", {}).get("initialDelayTime") != mcp_initial_delay_time:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/initialDelayTime".format(path, match.index), value=mcp_initial_delay_time))
                match.details["mcp"]["initialDelayTime"] = mcp_initial_delay_time

            if mcp_transmission_frequency_sec and match.details.get("mcp", {}).get("txFreq") != mcp_transmission_frequency_sec:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/txFreq".format(path, match.index), value=mcp_transmission_frequency_sec))
                match.details["mcp"]["txFreq"] = mcp_transmission_frequency_sec

            if mcp_transmission_frequency_msec and match.details.get("mcp", {}).get("txFreqMsec") != mcp_transmission_frequency_msec:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/txFreqMsec".format(path, match.index), value=mcp_transmission_frequency_msec))
                match.details["mcp"]["txFreqMsec"] = mcp_transmission_frequency_msec

            if mcp_grace_period_sec and match.details.get("mcp", {}).get("gracePeriod") != mcp_grace_period_sec:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/gracePeriod".format(path, match.index), value=mcp_grace_period_sec))
                match.details["mcp"]["gracePeriod"] = mcp_grace_period_sec

            if mcp_grace_period_msec and match.details.get("mcp", {}).get("gracePeriodMsec") != mcp_grace_period_msec:
                ops.append(dict(op="replace", path="{0}/{1}/mcp/gracePeriodMsec".format(path, match.index), value=mcp_grace_period_msec))
                match.details["mcp"]["gracePeriodMsec"] = mcp_grace_period_msec

            if port_channel_mode and match.details.get("portChannelPolicy", {}).get("mode") != port_channel_mode:
                ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/mode".format(path, match.index), value=port_channel_mode))
                match.details["portChannelPolicy"]["mode"] = port_channel_mode

            if min_links and match.details.get("portChannelPolicy", {}).get("minLinks") != min_links:
                ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/minLinks".format(path, match.index), value=min_links))
                match.details["portChannelPolicy"]["minLinks"] = min_links

            if max_links and match.details.get("portChannelPolicy", {}).get("maxLinks") != max_links:
                ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/maxLinks".format(path, match.index), value=max_links))
                match.details["portChannelPolicy"]["maxLinks"] = max_links

            if load_balance_hashing and match.details.get("portChannelPolicy", {}).get("hashFields") != load_balance_hashing:
                ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/hashFields".format(path, match.index), value=load_balance_hashing))
                match.details["portChannelPolicy"]["hashFields"] = load_balance_hashing

            if control:
                # existing control list is updated by the new control list
                control_list = []
                for item in control:
                    control_list.append(item)
                if match.details.get("portChannelPolicy", {}).get("control") != control_list:
                    ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/control".format(path, match.index), value=control_list))
                    match.details["portChannelPolicy"]["control"] = control_list

            mso.sanitize(match.details)

        else:
            payload = {
                "name": interface_policy_group,
                "type": interface_type,
                "templateId": mso_template.template.get("templateId"),
                "schemaId": mso_template.template.get("schemaId"),
            }

            if description:
                payload["description"] = description

            if domains:  # domains is a list
                domain_list = []
                # get names and uuids of existing domains
                existing_physical_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("domains", [])}
                existing_l3_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("l3Domains", [])}
                for item in domains:
                    if item in existing_physical_domains:
                        domain_list.append(existing_physical_domains[item])
                    elif item in existing_l3_domains:
                        domain_list.append(existing_l3_domains[item])
                    else:
                        mso.fail_json(msg="Domain '{0}' not found in the template '{1}'".format(item, template))
                payload["domains"] = domain_list

            if sync_e:
                existing_sync_e = {sync_e["name"]: sync_e["uuid"] for sync_e in template_info.get("syncEthIntfPolicies", [])}
                if sync_e in existing_sync_e:
                    payload["syncEthPolicy"] = existing_sync_e[sync_e]
                else:
                    mso.fail_json(msg="SyncE policy '{0}' not found in the template '{1}'".format(sync_e, template))

            if mcp_admin_state and mcp_admin_state == "disabled":
                mso.fail_json(msg="Access MACsec policy can only be set when mcp_admin_state is enabled")
            else:
                if access_mac_sec_policy:
                    existing_access_mac_sec_policy = {
                        access_mac_sec_policy["name"]: access_mac_sec_policy["uuid"] for access_mac_sec_policy in template_info.get("macsecPolicies", [])
                    }
                    if access_mac_sec_policy in existing_access_mac_sec_policy:
                        payload["accessMACsecPolicy"] = existing_access_mac_sec_policy[access_mac_sec_policy]
                    else:
                        mso.fail_json(msg="Access MACsec policy '{0}' not found in the template '{1}'".format(access_mac_sec_policy, template))

            # dictionaries
            # cdp
            if cdp_admin_state:
                payload["cdp"] = {"adminState": cdp_admin_state}
            # pfc
            if pfc_admin_state:
                payload["pfc"] = {"adminState": pfc_admin_state}
            # llfc
            payload["llfc"] = {}
            if llfc_transmit_state:
                payload["llfc"]["transmitState"] = llfc_transmit_state
            if llfc_receive_state:
                payload["llfc"]["receiveState"] = llfc_receive_state
            # stp
            payload["stp"] = {}
            if stp_bpdu_filter:
                payload["stp"]["bpduFilterEnabled"] = stp_bpdu_filter
            if stp_bpdu_guard:
                payload["stp"]["bpduGuardEnabled"] = stp_bpdu_guard
            # l2Interface
            payload["l2Interface"] = {}
            if l2_interface_qin_q:
                payload["l2Interface"]["qinq"] = l2_interface_qin_q
            if l2_interface_reflective_relay:
                payload["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay
            if vlan_scope:
                payload["l2Interface"]["vlanScope"] = vlan_scope
            # lldp
            payload["lldp"] = {}
            if lldp:
                if lldp == "disabled":
                    if not (lldp_receive_state == "disabled" and lldp_transmit_state == "disabled"):
                        mso.fail_json(msg="lldp_receive_state and lldp_transmit_state must be 'disabled' when LLDP is disabled")

                payload["lldp"]["receiveState"] = lldp_receive_state
                payload["lldp"]["transmitState"] = lldp_transmit_state

            # linkLevel
            payload["linkLevel"] = {}
            if link_level_debounce_interval:
                payload["linkLevel"]["debounceInterval"] = link_level_debounce_interval
            if link_level_bring_up_delay:
                payload["linkLevel"]["bringUpDelay"] = link_level_bring_up_delay
            if link_level_fec:
                payload["linkLevel"]["fec"] = link_level_fec
            if speed:
                payload["linkLevel"]["speed"] = speed
            if auto_negotiation:
                payload["linkLevel"]["autoNegotiation"] = auto_negotiation
            # mcp
            payload["mcp"] = {}
            if mcp_admin_state:
                payload["mcp"]["adminState"] = mcp_admin_state
            if mcp_strict_mode:
                payload["mcp"]["mcpMode"] = mcp_strict_mode
            if mcp_initial_delay_time:
                payload["mcp"]["initialDelayTime"] = mcp_initial_delay_time
            if mcp_transmission_frequency_sec:
                payload["mcp"]["txFreq"] = mcp_transmission_frequency_sec
            if mcp_transmission_frequency_msec:
                payload["mcp"]["txFreqMsec"] = mcp_transmission_frequency_msec
            if mcp_grace_period_sec:
                payload["mcp"]["gracePeriod"] = mcp_grace_period_sec
            if mcp_grace_period_msec:
                payload["mcp"]["gracePeriodMsec"] = mcp_grace_period_msec
            # portChannelPolicy
            payload["portChannelPolicy"] = {}
            if port_channel_mode:
                payload["portChannelPolicy"]["mode"] = port_channel_mode
            if min_links:
                payload["portChannelPolicy"]["minLinks"] = min_links
            if max_links:
                payload["portChannelPolicy"]["maxLinks"] = max_links
            if load_balance_hashing:
                payload["portChannelPolicy"]["hashFields"] = load_balance_hashing
            if control:
                control_list = []
                for item in control:
                    control_list.append(item)
                payload["portChannelPolicy"]["control"] = control_list

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        interface_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("interfacePolicyGroups", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            interface_policies,
            [KVPair("uuid", interface_policy_group_uuid) if interface_policy_group_uuid else KVPair("name", interface_policy_group)],
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
