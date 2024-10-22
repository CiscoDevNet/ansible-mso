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
    choices: [ physical, port_channel ]
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
    - The VLAN encapsulation value to map to EPG.
    - The default value is C(global).
    type: str
    choices: [ global, port_local ]
  cdp_admin_state:
    description:
    - The CDP admin state enables Cisco Discovery Protocol (CDP) on the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  domains:
    description:
    - The domains with which you want to associate this interface policy.
    - The domains must be defined in the same fabric policy template.
    - The old O(domains) will be replaced by the new entries during an update.
    - Providing an empty list will remove the O(domains) from the interface policy.
    type: list
    elements: str
  port_channel_mode:
    description:
    - The port channel mode of the interface policy group.
    - The default value is C(static_channel_mode_on).
    - The value is available only when the interface_type is C(port_channel).
    type: str
    choices: [ static_channel_mode_on, lacp_passive, lacp_active, mac_pinning, mac_pinning_physical_nic_load, use_explicit_failover_order ]
  min_links:
    description:
    - The minimum links of the interface policy group.
    - The default value is 1.
    - The value must be between 1 and 16.
    - The value is available only when the interface_type is C(port_channel).
    type: int
  max_links:
    description:
    - The maximum links of the interface policy group.
    - The default value is 16.
    - The value must be between 1 and 64.
    - The value is available only when the interface_type is C(port_channel).
    type: int
  controls:
    description:
    - The controls of the interface policy group.
    - The default value is C(fast_sel_hot_stdby), C(graceful_conv), C(susp_individual).
    - The value is available only when the interface_type is C(port_channel).
    - Providing an empty list will remove the O(controls) from the interface policy.
    - The old O(controls) will be replaced by the new entries during an update.
    type: list
    elements: str
    choices: [ fast_sel_hot_stdby, graceful_conv, susp_individual, load_defer, symmetric_hash ]
  load_balance_hashing:
    description:
    - The load balance hashing of the interface policy group.
    - The value is available only when the interface_type is C(port_channel).
    type: str
    choices: [ destination_ip, layer_4_destination_ip, layer_4_source_ip, source_ip ]
  synce:
    description:
    - The syncE policy assigned to the interface policy group.
    - The syncE policy must be defined in the same fabric policy template.
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
  l2_interface_qinq:
    description:
    - The QinQ enables mapping double-tagged VLAN traffic.
    - The default value is C(disabled).
    type: str
    choices: [ core_port, double_q_tag_port, edge_port, disabled ]
  l2_interface_reflective_relay:
    description:
    - The reflective relay enabled forwarding traffic.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  lldp:
    description:
    - The Link Layer Discovery Protocol (LLDP) on the interface.
    type: dict
    suboptions:
      status:
        description:
        - The status enables LLDP on the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      transmit_state:
        description:
        - The transmit state allows LLDP packets to be sent from the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      receive_state:
        description:
        - The receive state allows LLDP packets to be received by the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
  stp_bpdu_filter:
    description:
    - Enabling the Bridge Protocol Data Unit (BPDU) filter prevents any BPDUs on the port.
    - Disabling the BPDU filter allows BPDUs to be received on the port.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  stp_bpdu_guard:
    description:
    - Enabling the STP BPDU guard prevents the port from receiving BPDUs.
    - When C(enabled) the BPDUs are received on the port is put into 'errdisable' mode.
    - Disabling the STP BPDU guard allows BPDUs to be received on the port.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_transmit_state:
    description:
    - The LLFC transmit state allows Link Level Flow Control (LLFC) packets to be sent from the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  llfc_receive_state:
    description:
    - The LLFC receive state allows LLFC packets to be received by the interface.
    - The default value is C(disabled).
    type: str
    choices: [ enabled, disabled ]
  mcp:
    description:
    - The MisCabling Protocol (MCP) settings.
    type: dict
    suboptions:
      admin_state:
        description:
        - The MCP admin state enables MisCabling Protocol (MCP) on the interface.
        - The default value is C(enabled).
        type: str
        choices: [ enabled, disabled ]
      strict_mode:
        description:
        - The MCP strict mode.
        - The value is available only when the MCP admin_state is C(enabled).
        - The default value is C(off).
        type: str
        choices: [ 'on', 'off' ]
        aliases: [ mcp_mode ]
      initial_delay_time:
        description:
        - The MCP initial delay time in seconds.
        - The default value is 180.
        - The value must be between 0 and 1800.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      transmission_frequency_sec:
        description:
        - The MCP transmission frequency in seconds.
        - The default value is 2.
        - The value must be between 0 and 300.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      transmission_frequency_msec:
        description:
        - The MCP transmission frequency in milliseconds.
        - The default value is 0.
        - The value must be between 0 and 999.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      grace_period_sec:
        description:
        - The MCP grace period in seconds.
        - The default value is 3.
        - The value must be between 0 and 300.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
      grace_period_msec:
        description:
        - The MCP grace period in milliseconds.
        - The default value is 0.
        - The value must be between 0 and 999.
        - The value is available only when the MCP strict_mode is C(on).
        type: int
  pfc_admin_state:
    description:
    - The Priority Flow Control (PFC) admin state.
    - The default value is C(auto).
    type: str
    choices: [ 'on', 'off', auto ]
  access_macsec_policy:
    description:
    - The access MACsec policy.
    - The value is available only when the mcp_admin_state is C(enabled).
    - The MACsec policy must be defined in the same fabric policy template.
    type: str
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
- module: cisco.mso.ndo_macsec_policy
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

- name: Create an Interface policy group of interface_type port_channel
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_port_channel
  description: "Interface Policy Group for Ansible Test"
  interface_type: port_channel
  state: present

- name: Create an Interface policy group with all attributes
  cisco.mso.ndo_interface_setting:
  host: mso_host
  username: admin
  password: SomeSecretPassword
  template: ansible_test_template
  interface_policy_group: ansible_test_interface_policy_group_all
  description: "Interface Policy Group for Ansible Test"
  interface_type: port_channel
  speed: 1G
  auto_negotiation: on_enforce
  vlan_scope: port_local
  cdp_admin_state: enabled
  port_channel_mode: lacp_active
  min_links: 1
  max_links: 16
  controls: ["fast_sel_hot_stdby", "graceful_conv", "susp_individual"]
  load_balance_hashing: destination_ip
  synce: ansible_test_sync_e
  link_level_debounce_interval: 100
  link_level_bring_up_delay: 0
  link_level_fec: ieee_rs_fec
  l2_interface_qinq: edge_port
  l2_interface_reflective_relay: enabled
  lldp:
    status: enabled
    transmit_state: enabled
    receive_state: enabled
  domains:
    - ansible_test_domain1
    - ansible_test_domain2
  stp_bpdu_filter: enabled
  stp_bpdu_guard: enabled
  llfc_transmit_state: enabled
  llfc_receive_state: enabled
  mcp:
    admin_state: enabled
    strict_mode: 'on'
    initial_delay_time: 180
    transmission_frequency_sec: 2
    transmission_frequency_msec: 10
    grace_period_sec: 3
    grace_period_msec: 10
  pfc_admin_state: 'on'
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
    L2_INTERFACE_QINQ_MAP,
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
            interface_type=dict(type="str", choices=["physical", "port_channel"]),
            speed=dict(type="str", choices=["100M", "1G", "10G", "25G", "40G", "50G", "100G", "200G", "400G", "inherit"]),
            auto_negotiation=dict(type="str", choices=["on", "off", "on_enforce"]),
            vlan_scope=dict(type="str", choices=["global", "port_local"]),
            cdp_admin_state=dict(type="str", choices=["enabled", "disabled"]),
            lldp=dict(
                type="dict",
                options=dict(
                    status=dict(type="str", choices=["enabled", "disabled"]),
                    transmit_state=dict(type="str", choices=["enabled", "disabled"]),
                    receive_state=dict(type="str", choices=["enabled", "disabled"]),
                ),
            ),
            domains=dict(type="list", elements="str"),
            port_channel_mode=dict(type="str", choices=list(PORT_CHANNEL_MODE_MAP)),
            min_links=dict(type="int"),
            max_links=dict(type="int"),
            controls=dict(type="list", elements="str", choices=list(CONTROL_MAP)),
            load_balance_hashing=dict(type="str", choices=list(LOAD_BALANCE_HASHING_MAP)),
            synce=dict(type="str"),
            link_level_debounce_interval=dict(type="int"),
            link_level_bring_up_delay=dict(type="int"),
            link_level_fec=dict(type="str", choices=list(LINK_LEVEL_FEC_MAP)),
            l2_interface_qinq=dict(type="str", choices=list(L2_INTERFACE_QINQ_MAP)),
            l2_interface_reflective_relay=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_filter=dict(type="str", choices=["enabled", "disabled"]),
            stp_bpdu_guard=dict(type="str", choices=["enabled", "disabled"]),
            llfc_transmit_state=dict(type="str", choices=["enabled", "disabled"]),
            llfc_receive_state=dict(type="str", choices=["enabled", "disabled"]),
            mcp=dict(
                type="dict",
                options=dict(
                    admin_state=dict(type="str", choices=["enabled", "disabled"]),
                    strict_mode=dict(type="str", choices=["on", "off"], aliases=["mcp_mode"]),
                    initial_delay_time=dict(type="int"),
                    transmission_frequency_sec=dict(type="int"),
                    transmission_frequency_msec=dict(type="int"),
                    grace_period_sec=dict(type="int"),
                    grace_period_msec=dict(type="int"),
                ),
            ),
            pfc_admin_state=dict(type="str", choices=["on", "off", "auto"]),
            access_macsec_policy=dict(type="str"),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["interface_policy_group", "interface_policy_group_uuid"], True],
            ["state", "absent", ["interface_policy_group", "interface_policy_group_uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    description = module.params.get("description")
    interface_type = module.params.get("interface_type")
    if interface_type == "port_channel":
        interface_type = "portchannel"
    speed = module.params.get("speed")
    auto_negotiation = module.params.get("auto_negotiation")
    if auto_negotiation == "on_enforce":
        auto_negotiation = "on-enforce"
    vlan_scope = module.params.get("vlan_scope")
    if vlan_scope == "port_local":
        vlan_scope = "portlocal"
    cdp_admin_state = module.params.get("cdp_admin_state")
    lldp = module.params.get("lldp")
    domains = module.params.get("domains")
    port_channel_mode = PORT_CHANNEL_MODE_MAP.get(module.params.get("port_channel_mode"))
    min_links = module.params.get("min_links")
    max_links = module.params.get("max_links")
    controls = module.params.get("controls")
    if controls:
        controls = [CONTROL_MAP.get(v) for v in controls]
    load_balance_hashing = LOAD_BALANCE_HASHING_MAP.get(module.params.get("load_balance_hashing"))
    synce = module.params.get("synce")
    link_level_debounce_interval = module.params.get("link_level_debounce_interval")
    link_level_bring_up_delay = module.params.get("link_level_bring_up_delay")
    link_level_fec = LINK_LEVEL_FEC_MAP.get(module.params.get("link_level_fec"))
    l2_interface_qinq = L2_INTERFACE_QINQ_MAP.get(module.params.get("l2_interface_qinq"))
    l2_interface_reflective_relay = module.params.get("l2_interface_reflective_relay")
    stp_bpdu_filter = module.params.get("stp_bpdu_filter")
    stp_bpdu_guard = module.params.get("stp_bpdu_guard")
    llfc_transmit_state = module.params.get("llfc_transmit_state")
    llfc_receive_state = module.params.get("llfc_receive_state")
    mcp = module.params.get("mcp")
    pfc_admin_state = module.params.get("pfc_admin_state")
    access_macsec_policy = module.params.get("access_macsec_policy")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/interfacePolicyGroups"
    object_description = "Interface Policy Groups"

    template_info = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {})

    existing_interface_policies = template_info.get("interfacePolicyGroups", [])
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
                mso.fail_json(msg="Interface type cannot be changed.")

            if domains:
                domain_uuid = validate_domains(mso, domains, template, template_info)
                if set(domain_uuid) != set(match.details.get("domains", [])):
                    ops.append(dict(op="replace", path="{0}/{1}/domains".format(path, match.index), value=domain_uuid))
                match.details["domains"] = domain_uuid
            elif domains == []:
                ops.append(dict(op="remove", path="{0}/{1}/domains".format(path, match.index)))
                match.details.pop("domains", None)

            if synce:
                existing_sync_e = validate_sync_e(mso, synce, template, template_info)
                if existing_sync_e[synce] != match.details.get("syncEthPolicy"):
                    ops.append(dict(op="replace", path="{0}/{1}/syncEthPolicy".format(path, match.index), value=existing_sync_e[synce]))
                    match.details["syncEthPolicy"] = existing_sync_e[synce]

            if access_macsec_policy:
                existing_access_macsec_policy = validate_macsec_policy(mso, access_macsec_policy, template, template_info)
                if existing_access_macsec_policy[access_macsec_policy] != match.details.get("accessMACsecPolicy"):
                    ops.append(
                        dict(
                            op="replace",
                            path="{0}/{1}/accessMACsecPolicy".format(path, match.index),
                            value=existing_access_macsec_policy[access_macsec_policy],
                        )
                    )
                    match.details["accessMACsecPolicy"] = existing_access_macsec_policy[access_macsec_policy]

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

            if l2_interface_qinq and match.details.get("l2Interface", {}).get("qinq") != l2_interface_qinq:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/qinq".format(path, match.index), value=l2_interface_qinq))
                match.details["l2Interface"]["qinq"] = l2_interface_qinq

            if l2_interface_reflective_relay and match.details.get("l2Interface", {}).get("reflectiveRelay") != l2_interface_reflective_relay:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/reflectiveRelay".format(path, match.index), value=l2_interface_reflective_relay))
                match.details["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay

            if vlan_scope and match.details.get("l2Interface", {}).get("vlanScope") != vlan_scope:
                ops.append(dict(op="replace", path="{0}/{1}/l2Interface/vlanScope".format(path, match.index), value=vlan_scope))
                match.details["l2Interface"]["vlanScope"] = vlan_scope

            if lldp:
                validate_lldp(mso, lldp)
                if lldp["receive_state"] and match.details.get("lldp", {}).get("receiveState") != lldp["receive_state"]:
                    ops.append(dict(op="replace", path="{0}/{1}/lldp/receiveState".format(path, match.index), value=lldp["receive_state"]))
                    match.details["lldp"]["receiveState"] = lldp["receive_state"]
                if lldp["transmit_state"] and match.details.get("lldp", {}).get("transmitState") != lldp["transmit_state"]:
                    ops.append(dict(op="replace", path="{0}/{1}/lldp/transmitState".format(path, match.index), value=lldp["transmit_state"]))
                    match.details["lldp"]["transmitState"] = lldp["transmit_state"]

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

            if mcp:
                if mcp["admin_state"] and match.details.get("mcp", {}).get("adminState") != mcp["admin_state"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/adminState".format(path, match.index), value=mcp["admin_state"]))
                    match.details["mcp"]["adminState"] = mcp["admin_state"]
                if mcp["strict_mode"] and match.details.get("mcp", {}).get("mcpMode") != mcp["strict_mode"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/mcpMode".format(path, match.index), value=mcp["strict_mode"]))
                    match.details["mcp"]["mcpMode"] = mcp["strict_mode"]
                if mcp["initial_delay_time"] and match.details.get("mcp", {}).get("initialDelayTime") != mcp["initial_delay_time"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/initialDelayTime".format(path, match.index), value=mcp["initial_delay_time"]))
                    match.details["mcp"]["initialDelayTime"] = mcp["initial_delay_time"]
                if mcp["transmission_frequency_sec"] and match.details.get("mcp", {}).get("txFreq") != mcp["transmission_frequency_sec"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/txFreq".format(path, match.index), value=mcp["transmission_frequency_sec"]))
                    match.details["mcp"]["txFreq"] = mcp["transmission_frequency_sec"]
                if mcp["transmission_frequency_msec"] and match.details.get("mcp", {}).get("txFreqMsec") != mcp["transmission_frequency_msec"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/txFreqMsec".format(path, match.index), value=mcp["transmission_frequency_msec"]))
                    match.details["mcp"]["txFreqMsec"] = mcp["transmission_frequency_msec"]
                if mcp["grace_period_sec"] and match.details.get("mcp", {}).get("gracePeriod") != mcp["grace_period_sec"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/gracePeriod".format(path, match.index), value=mcp["grace_period_sec"]))
                    match.details["mcp"]["gracePeriod"] = mcp["grace_period_sec"]
                if mcp["grace_period_msec"] and match.details.get("mcp", {}).get("gracePeriodMsec") != mcp["grace_period_msec"]:
                    ops.append(dict(op="replace", path="{0}/{1}/mcp/gracePeriodMsec".format(path, match.index), value=mcp["grace_period_msec"]))
                    match.details["mcp"]["gracePeriodMsec"] = mcp["grace_period_msec"]

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

            if controls and match.details.get("portChannelPolicy", {}).get("control") != controls:
                ops.append(dict(op="replace", path="{0}/{1}/portChannelPolicy/control".format(path, match.index), value=controls))
                match.details["portChannelPolicy"]["control"] = controls
            elif controls == []:
                ops.append(dict(op="remove", path="{0}/{1}/portChannelPolicy/control".format(path, match.index)))
                match.details.pop("controls", None)

            mso.sanitize(match.details)

        else:
            if not interface_type:
                mso.fail_json(msg="Error: Missing required argument 'interface_type' for creating an Interface Policy Group.")
            payload = {
                "name": interface_policy_group,
                "type": interface_type,
                "templateId": mso_template.template.get("templateId"),
                "schemaId": mso_template.template.get("schemaId"),
                "llfc": {},
                "stp": {},
                "l2Interface": {},
                "lldp": {},
                "linkLevel": {},
                "mcp": {},
                "portChannelPolicy": {},
            }

            if description:
                payload["description"] = description

            if domains:
                domain_uuid = validate_domains(mso, domains, template, template_info)
                payload["domains"] = domain_uuid

            if synce:
                existing_sync_e = validate_sync_e(mso, synce, template, template_info)
                payload["syncEthPolicy"] = existing_sync_e[synce]

            if access_macsec_policy:
                existing_access_macsec_policy = validate_macsec_policy(mso, access_macsec_policy, template, template_info)
                payload["accessMACsecPolicy"] = existing_access_macsec_policy[access_macsec_policy]

            if cdp_admin_state:
                payload["cdp"] = {"adminState": cdp_admin_state}

            if pfc_admin_state:
                payload["pfc"] = {"adminState": pfc_admin_state}

            if llfc_transmit_state:
                payload["llfc"]["transmitState"] = llfc_transmit_state
            if llfc_receive_state:
                payload["llfc"]["receiveState"] = llfc_receive_state

            if stp_bpdu_filter:
                payload["stp"]["bpduFilterEnabled"] = stp_bpdu_filter
            if stp_bpdu_guard:
                payload["stp"]["bpduGuardEnabled"] = stp_bpdu_guard

            if l2_interface_qinq:
                payload["l2Interface"]["qinq"] = l2_interface_qinq
            if l2_interface_reflective_relay:
                payload["l2Interface"]["reflectiveRelay"] = l2_interface_reflective_relay
            if vlan_scope:
                payload["l2Interface"]["vlanScope"] = vlan_scope

            if lldp:
                validate_lldp(mso, lldp)
                payload["lldp"]["receiveState"] = lldp["receive_state"]
                payload["lldp"]["transmitState"] = lldp["transmit_state"]

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

            if mcp:
                if mcp["admin_state"]:
                    payload["mcp"]["adminState"] = mcp["admin_state"]
                if mcp["strict_mode"]:
                    payload["mcp"]["mcpMode"] = mcp["strict_mode"]
                if mcp["initial_delay_time"]:
                    payload["mcp"]["initialDelayTime"] = mcp["initial_delay_time"]
                if mcp["transmission_frequency_sec"]:
                    payload["mcp"]["txFreq"] = mcp["transmission_frequency_sec"]
                if mcp["transmission_frequency_msec"]:
                    payload["mcp"]["txFreqMsec"] = mcp["transmission_frequency_msec"]
                if mcp["grace_period_sec"]:
                    payload["mcp"]["gracePeriod"] = mcp["grace_period_sec"]
                if mcp["grace_period_msec"]:
                    payload["mcp"]["gracePeriodMsec"] = mcp["grace_period_msec"]

            if port_channel_mode:
                payload["portChannelPolicy"]["mode"] = port_channel_mode
            if min_links:
                payload["portChannelPolicy"]["minLinks"] = min_links
            if max_links:
                payload["portChannelPolicy"]["maxLinks"] = max_links
            if load_balance_hashing:
                payload["portChannelPolicy"]["hashFields"] = load_balance_hashing
            if controls:
                payload["portChannelPolicy"]["control"] = controls

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


def validate_domains(mso, domains, template, template_info):
    domain_uuid = []
    existing_physical_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("domains", [])}
    existing_l3_domains = {domain["name"]: domain["uuid"] for domain in template_info.get("l3Domains", [])}
    for item in domains:
        if item in existing_physical_domains:
            domain_uuid.append(existing_physical_domains[item])
        elif item in existing_l3_domains:
            domain_uuid.append(existing_l3_domains[item])
        else:
            mso.fail_json(msg="Domain '{0}' not found in the template '{1}'.".format(item, template))
    return domain_uuid


def validate_macsec_policy(mso, access_macsec_policy, template, template_info):
    existing_access_macsec_policy = {macsec_policy["name"]: macsec_policy["uuid"] for macsec_policy in template_info.get("macsecPolicies", [])}
    if access_macsec_policy not in existing_access_macsec_policy:
        mso.fail_json(msg="Access MACsec policy '{0}' not found in the template '{1}'.".format(access_macsec_policy, template))
    return existing_access_macsec_policy


def validate_sync_e(mso, synce, template, template_info):
    existing_sync_e = {synce["name"]: synce["uuid"] for synce in template_info.get("syncEthIntfPolicies", [])}
    if synce not in existing_sync_e:
        mso.fail_json(msg="SyncE policy '{0}' not found in the template '{1}'.".format(synce, template))
    return existing_sync_e


def validate_lldp(mso, lldp):
    if lldp["status"] == "disabled" and not (lldp["receive_state"] == "disabled" and lldp["transmit_state"] == "disabled"):
        mso.fail_json(msg="LLDP receive_state and transmit_state must be 'disabled' when LLDP status is disabled.")


if __name__ == "__main__":
    main()
