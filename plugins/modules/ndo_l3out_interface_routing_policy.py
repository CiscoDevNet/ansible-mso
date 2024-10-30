#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_interface_routing_policy
short_description: Manage L3Out Interface Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Interface Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    type: str
    required: true
  name:
    description:
    - The name of the L3Out Interface Routing Policy.
    type: str
    aliases: [ l3out_interface_routing_policy_name ]
  uuid:
    description:
    - The UUID of the L3Out Interface Routing Policy.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ l3out_interface_routing_policy_uuid ]
  description:
    description:
    - The description of the L3Out Interface Routing Policy.
    type: str
  bfd_multi_hop_settings:
    description:
    - The BFD MultiHop Settings configuration of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BFD MultiHop Settings.
        - Use C(disabled) to remove the BFD MultiHop Settings.
        type: str
        choices: [ enabled, disabled ]
      admin_state:
        description:
        - The administrative state of the BFD MultiHop Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      detection_multiplier:
        description:
        - The detection multiplier of the BFD MultiHop Settings.
        - Defaults to 3 when unset during creation.
        - The value must be between 1 and 50.
        type: int
      min_receive_interval:
        description:
        - The minimum receive interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
      min_transmit_interval:
        description:
        - The minimum transmit interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
  bfd_settings:
    description:
    - The BFD Settings of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BFD Settings.
        - Use C(disabled) to remove the BFD Settings.
        type: str
        choices: [ enabled, disabled ]
      admin_state:
        description:
        - The administrative state of the BFD Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      detection_multiplier:
        description:
        - The detection multiplier of the BFD Settings.
        - Defaults to 3 when unset during creation.
        - The value must be between 1 and 50.
        type: int
      min_receive_interval:
        description:
        - The minimum receive interval of the BFD Settings.
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999 microseconds.
        type: int
      min_transmit_interval:
        description:
        - The minimum transmit interval of the BFD Settings.
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999 microseconds.
        type: int
      echo_receive_interval:
        description:
        - The echo receive interval of the BFD Settings.
        - Defaults to 50 when unset during creation.
        - The value must be between 50 and 999.
        type: int
      echo_admin_state:
        description:
        - The echo administrative state of the BFD Settings.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      interface_control:
        description:
        - The interface control of the BFD Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
  ospf_interface_settings:
    description:
    - The OSPF Interface Settings of the L3Out Interface Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the OSPF Interface Settings.
        - Use C(disabled) to remove the OSPF Interface Settings.
        type: str
        choices: [ enabled, disabled ]
      network_type:
        description:
        - The network type of the OSPF Interface Settings.
        - Defaults to C(broadcast) when unset during creation.
        type: str
        choices: [ broadcast, point_to_point ]
      priority:
        description:
        - The priority of the OSPF Interface Settings.
        - Defaults to 1 when unset during creation.
        - The value must be between 0 and 255.
        type: int
      cost_of_interface:
        description:
        - The cost of the OSPF Interface Settings.
        - Defaults to 0 when unset during creation.
        - The value must be between 0 and 65535.
        type: int
      hello_interval:
        description:
        - The hello interval of the OSPF Interface Settings.
        - Defaults to 10 when unset during creation.
        - The value must be between 1 and 65535 seconds.
        type: int
      dead_interval:
        description:
        - The dead interval of the OSPF Interface Settings.
        - Defaults to 40 when unset during creation.
        - The value must be between 1 and 65535 seconds.
        type: int
      retransmit_interval:
        description:
        - The retransmit interval of the OSPF Interface Settings.
        - Defaults to 5 when unset during creation.
        - The value must be between 1 and 65535 seconds.
        type: int
      transmit_delay:
        description:
        - The transmit delay of the OSPF Interface Settings.
        - Defaults to 1 when unset during creation.
        - The value must be between 1 and 450 seconds.
        type: int
      advertise_subnet:
        description:
        - The advertise subnet of the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      bfd:
        description:
        - The Bidirectional Forwarding Detection (BFD) of the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      mtu_ignore:
        description:
        - The Maximum Transmission Unit (MTU) of the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      passive_participation:
        description:
        - The passive participation of the OSPF Interface Settings.
        - Defaults to C(disabled) when unset during creation.
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
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out Interface Routing Policy with default values
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1
    bfd_settings:
      state: enabled
    bfd_multi_hop_settings:
      state: enabled
    state: present
  register: irp_1_present

- name: Update an existing L3Out Interface Routing Policy with UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    name: irp_1_updated
    bfd_multi_hop_settings:
      admin_state: disabled
      detection_multiplier: 10
      min_receive_interval: 255
      min_transmit_interval: 255
    bfd_settings:
      admin_state: disabled
      detection_multiplier: 10
      min_receive_interval: 266
      min_transmit_interval: 266
      echo_receive_interval: 60
      echo_admin_state: disabled
      interface_control: enabled
    ospf_interface_settings:
      network_type: point_to_point
      priority: 10
      cost_of_interface: 100
      advertise_subnet: enabled
      bfd: enabled
      mtu_ignore: enabled
      passive_participation: enabled
      hello_interval: 20
      dead_interval: 30
      retransmit_interval: 20
      transmit_delay: 10
    state: present
  register: irp_1_present

- name: Clear an existing L3Out Interface Routing Policy BFD and OSPF interface settings
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ irp_1_present.current.uuid }}"
    bfd_settings:
      state: disabled
    ospf_interface_settings:
      state: disabled
    state: present

- name: Query a L3Out Interface Routing Policies with name
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1_updated
    state: query
  register: query_with_name

- name: Query a L3Out Interface Routing Policies with UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_with_name.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all L3Out Interface Routing Policies
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a L3Out Interface Routing Policy
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: irp_1_updated
    state: absent

- name: Delete a L3Out Interface Routing Policy using UUID
  cisco.mso.ndo_l3out_interface_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_with_name.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_DISABLED_BOOLEAN_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        uuid=dict(type="str", aliases=["l3out_interface_routing_policy_uuid"]),
        name=dict(type="str", aliases=["l3out_interface_routing_policy_name"]),
        description=dict(type="str"),
        bfd_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                detection_multiplier=dict(type="int"),
                min_receive_interval=dict(type="int"),
                min_transmit_interval=dict(type="int"),
                echo_receive_interval=dict(type="int"),
                echo_admin_state=dict(type="str", choices=["enabled", "disabled"]),
                interface_control=dict(type="str", choices=["enabled", "disabled"]),
            ),
        ),
        bfd_multi_hop_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                detection_multiplier=dict(type="int"),
                min_receive_interval=dict(type="int"),
                min_transmit_interval=dict(type="int"),
            ),
        ),
        ospf_interface_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                network_type=dict(type="str", choices=["broadcast", "point_to_point"]),
                priority=dict(type="int"),
                cost_of_interface=dict(type="int"),
                advertise_subnet=dict(type="str", choices=["enabled", "disabled"]),
                bfd=dict(type="str", choices=["enabled", "disabled"]),
                mtu_ignore=dict(type="str", choices=["enabled", "disabled"]),
                passive_participation=dict(type="str", choices=["enabled", "disabled"]),
                hello_interval=dict(type="int"),
                dead_interval=dict(type="int"),
                retransmit_interval=dict(type="int"),
                transmit_delay=dict(type="int"),
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
    bfd_settings = module.params.get("bfd_settings")
    bfd_multi_hop_settings = module.params.get("bfd_multi_hop_settings")
    ospf_interface_settings = module.params.get("ospf_interface_settings")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    l3out_interface_routing_policy = mso_template.get_l3out_interface_routing_policy_object(uuid, name)

    if (uuid or name) and l3out_interface_routing_policy:
        mso.existing = mso.previous = copy.deepcopy(l3out_interface_routing_policy.details)  # Query a specific object
    elif l3out_interface_routing_policy:
        mso.existing = l3out_interface_routing_policy  # Query all objects

    if state != "query":
        interface_routing_policy_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/{0}".format(
            l3out_interface_routing_policy.index if l3out_interface_routing_policy else "-"
        )

    ops = []
    if state == "present":
        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)

            if name and proposed_payload.get("name") != name:
                ops.append(dict(op="replace", path="{0}/name".format(interface_routing_policy_path), value=name))
                proposed_payload["name"] = name

            if description is not None and proposed_payload.get("description") != description:
                ops.append(dict(op="replace", path="{0}/description".format(interface_routing_policy_path), value=description))
                proposed_payload["description"] = description

            # BFD MultiHop Settings
            if bfd_multi_hop_settings is not None:
                if bfd_multi_hop_settings.get("state") == "disabled" and proposed_payload.get("bfdMultiHopPol"):
                    proposed_payload.pop("bfdMultiHopPol", None)
                    ops.append(dict(op="remove", path="{0}/bfdMultiHopPol".format(interface_routing_policy_path)))

                elif bfd_multi_hop_settings.get("state") != "disabled":
                    if not proposed_payload.get("bfdMultiHopPol"):
                        proposed_payload["bfdMultiHopPol"] = dict()
                        ops.append(dict(op="replace", path="{0}/bfdMultiHopPol".format(interface_routing_policy_path), value=dict()))

                    if bfd_multi_hop_settings.get("admin_state") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "adminState"
                    ) != bfd_multi_hop_settings.get("admin_state"):
                        proposed_payload["bfdMultiHopPol"]["adminState"] = bfd_multi_hop_settings.get("admin_state")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/adminState".format(interface_routing_policy_path),
                                value=bfd_multi_hop_settings.get("admin_state"),
                            )
                        )

                    if bfd_multi_hop_settings.get("detection_multiplier") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "detectionMultiplier"
                    ) != bfd_multi_hop_settings.get("detection_multiplier"):
                        proposed_payload["bfdMultiHopPol"]["detectionMultiplier"] = bfd_multi_hop_settings.get("detection_multiplier")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/detectionMultiplier".format(interface_routing_policy_path),
                                value=bfd_multi_hop_settings.get("detection_multiplier"),
                            )
                        )

                    if bfd_multi_hop_settings.get("min_receive_interval") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "minRxInterval"
                    ) != bfd_multi_hop_settings.get("min_receive_interval"):
                        proposed_payload["bfdMultiHopPol"]["minRxInterval"] = bfd_multi_hop_settings.get("min_receive_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/minRxInterval".format(interface_routing_policy_path),
                                value=bfd_multi_hop_settings.get("min_receive_interval"),
                            )
                        )

                    if bfd_multi_hop_settings.get("min_transmit_interval") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "minTxInterval"
                    ) != bfd_multi_hop_settings.get("min_transmit_interval"):
                        proposed_payload["bfdMultiHopPol"]["minTxInterval"] = bfd_multi_hop_settings.get("min_transmit_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/minTxInterval".format(interface_routing_policy_path),
                                value=bfd_multi_hop_settings.get("min_transmit_interval"),
                            )
                        )

            # BFD Settings
            if bfd_settings is not None:
                if bfd_settings.get("state") == "disabled" and proposed_payload.get("bfdPol"):
                    proposed_payload.pop("bfdPol", None)
                    ops.append(dict(op="remove", path="{0}/bfdPol".format(interface_routing_policy_path)))

                elif bfd_settings.get("state") != "disabled":
                    if not proposed_payload.get("bfdPol"):
                        proposed_payload["bfdPol"] = dict()
                        ops.append(dict(op="replace", path="{0}/bfdPol".format(interface_routing_policy_path), value=dict()))

                    if bfd_settings.get("admin_state") is not None and proposed_payload.get("bfdPol").get("adminState") != bfd_settings.get("admin_state"):
                        proposed_payload["bfdPol"]["adminState"] = bfd_settings.get("admin_state")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/adminState".format(interface_routing_policy_path),
                                value=bfd_settings.get("admin_state"),
                            )
                        )

                    if bfd_settings.get("detection_multiplier") is not None and proposed_payload.get("bfdPol").get("detectionMultiplier") != bfd_settings.get(
                        "detection_multiplier"
                    ):
                        proposed_payload["bfdPol"]["detectionMultiplier"] = bfd_settings.get("detection_multiplier")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/detectionMultiplier".format(interface_routing_policy_path),
                                value=bfd_settings.get("detection_multiplier"),
                            )
                        )

                    if bfd_settings.get("min_receive_interval") is not None and proposed_payload.get("bfdPol").get("minRxInterval") != bfd_settings.get(
                        "min_receive_interval"
                    ):
                        proposed_payload["bfdPol"]["minRxInterval"] = bfd_settings.get("min_receive_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/minRxInterval".format(interface_routing_policy_path),
                                value=bfd_settings.get("min_receive_interval"),
                            )
                        )

                    if bfd_settings.get("min_transmit_interval") is not None and proposed_payload.get("bfdPol").get("minTxInterval") != bfd_settings.get(
                        "min_transmit_interval"
                    ):
                        proposed_payload["bfdPol"]["minTxInterval"] = bfd_settings.get("min_transmit_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/minTxInterval".format(interface_routing_policy_path),
                                value=bfd_settings.get("min_transmit_interval"),
                            )
                        )

                    if bfd_settings.get("echo_receive_interval") is not None and proposed_payload.get("bfdPol").get("echoRxInterval") != bfd_settings.get(
                        "echo_receive_interval"
                    ):
                        proposed_payload["bfdPol"]["echoRxInterval"] = bfd_settings.get("echo_receive_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/echoRxInterval".format(interface_routing_policy_path),
                                value=bfd_settings.get("echo_receive_interval"),
                            )
                        )

                    if bfd_settings.get("echo_admin_state") is not None and proposed_payload.get("bfdPol").get("echoAdminState") != bfd_settings.get(
                        "echo_admin_state"
                    ):
                        proposed_payload["bfdPol"]["echoAdminState"] = bfd_settings.get("echo_admin_state")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/echoAdminState".format(interface_routing_policy_path),
                                value=bfd_settings.get("echo_admin_state"),
                            )
                        )

                    interface_control_value = ENABLED_DISABLED_BOOLEAN_MAP.get(bfd_settings.get("interface_control"))
                    if interface_control_value is not None and proposed_payload.get("bfdPol").get("gracefulRestartHelper") is not interface_control_value:
                        proposed_payload["bfdPol"]["gracefulRestartHelper"] = interface_control_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdPol/gracefulRestartHelper".format(interface_routing_policy_path),
                                value=interface_control_value,
                            )
                        )

            # OSPF Interface Settings
            if ospf_interface_settings is not None:
                if ospf_interface_settings.get("state") == "disabled" and proposed_payload.get("ospfIntfPol"):
                    proposed_payload.pop("ospfIntfPol", None)
                    ops.append(dict(op="remove", path="{0}/ospfIntfPol".format(interface_routing_policy_path)))

                elif ospf_interface_settings.get("state") != "disabled":
                    if not proposed_payload.get("ospfIntfPol"):
                        proposed_payload["ospfIntfPol"] = dict()
                        proposed_payload["ospfIntfPol"]["ifControl"] = dict()
                        ops.append(dict(op="replace", path="{0}/ospfIntfPol".format(interface_routing_policy_path), value=dict()))
                        ops.append(dict(op="replace", path="{0}/ospfIntfPol/ifControl".format(interface_routing_policy_path), value=dict()))

                    network_type_value = get_ospf_network_type(ospf_interface_settings.get("network_type"))
                    if network_type_value is not None and proposed_payload.get("ospfIntfPol").get("networkType") != network_type_value:
                        proposed_payload["ospfIntfPol"]["networkType"] = network_type_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/networkType".format(interface_routing_policy_path),
                                value=network_type_value,
                            )
                        )

                    if ospf_interface_settings.get("priority") is not None and proposed_payload.get("ospfIntfPol").get("prio") != ospf_interface_settings.get(
                        "priority"
                    ):
                        proposed_payload["ospfIntfPol"]["prio"] = ospf_interface_settings.get("priority")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/prio".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("priority"),
                            )
                        )

                    if ospf_interface_settings.get("cost_of_interface") is not None and proposed_payload.get("ospfIntfPol").get(
                        "cost"
                    ) != ospf_interface_settings.get("cost_of_interface"):
                        proposed_payload["ospfIntfPol"]["cost"] = ospf_interface_settings.get("cost_of_interface")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/cost".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("cost_of_interface"),
                            )
                        )

                    if ospf_interface_settings.get("hello_interval") is not None and proposed_payload.get("ospfIntfPol").get(
                        "helloInterval"
                    ) != ospf_interface_settings.get("hello_interval"):
                        proposed_payload["ospfIntfPol"]["helloInterval"] = ospf_interface_settings.get("hello_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/helloInterval".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("hello_interval"),
                            )
                        )

                    if ospf_interface_settings.get("dead_interval") is not None and proposed_payload.get("ospfIntfPol").get(
                        "deadInterval"
                    ) != ospf_interface_settings.get("dead_interval"):
                        proposed_payload["ospfIntfPol"]["deadInterval"] = ospf_interface_settings.get("dead_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/deadInterval".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("dead_interval"),
                            )
                        )

                    if ospf_interface_settings.get("retransmit_interval") is not None and proposed_payload.get("ospfIntfPol").get(
                        "retransmitInterval"
                    ) != ospf_interface_settings.get("retransmit_interval"):
                        proposed_payload["ospfIntfPol"]["retransmitInterval"] = ospf_interface_settings.get("retransmit_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/retransmitInterval".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("retransmit_interval"),
                            )
                        )

                    if ospf_interface_settings.get("transmit_delay") is not None and proposed_payload.get("ospfIntfPol").get(
                        "transmitDelay"
                    ) != ospf_interface_settings.get("transmit_delay"):
                        proposed_payload["ospfIntfPol"]["transmitDelay"] = ospf_interface_settings.get("transmit_delay")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/transmitDelay".format(interface_routing_policy_path),
                                value=ospf_interface_settings.get("transmit_delay"),
                            )
                        )

                    advertise_subnet_value = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("advertise_subnet"))
                    if (
                        advertise_subnet_value is not None
                        and proposed_payload.get("ospfIntfPol").get("ifControl").get("advertiseSubnet") is not advertise_subnet_value
                    ):
                        proposed_payload["ospfIntfPol"]["ifControl"]["advertiseSubnet"] = advertise_subnet_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/ifControl/advertiseSubnet".format(interface_routing_policy_path),
                                value=advertise_subnet_value,
                            )
                        )

                    bfd_value = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("bfd"))
                    if bfd_value is not None and proposed_payload.get("ospfIntfPol").get("ifControl").get("bfd") is not bfd_value:
                        proposed_payload["ospfIntfPol"]["ifControl"]["bfd"] = bfd_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/ifControl/bfd".format(interface_routing_policy_path),
                                value=bfd_value,
                            )
                        )

                    mtu_ignore_value = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("mtu_ignore"))
                    if mtu_ignore_value is not None and proposed_payload.get("ospfIntfPol").get("ifControl").get("ignoreMtu") is not mtu_ignore_value:
                        proposed_payload["ospfIntfPol"]["ifControl"]["ignoreMtu"] = mtu_ignore_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/ifControl/ignoreMtu".format(interface_routing_policy_path),
                                value=mtu_ignore_value,
                            )
                        )

                    passive_participation_value = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("passive_participation"))
                    if (
                        passive_participation_value is not None
                        and proposed_payload.get("ospfIntfPol").get("ifControl").get("passiveParticipation") is not passive_participation_value
                    ):
                        proposed_payload["ospfIntfPol"]["ifControl"]["passiveParticipation"] = passive_participation_value
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/ospfIntfPol/ifControl/passiveParticipation".format(interface_routing_policy_path),
                                value=passive_participation_value,
                            )
                        )

            mso.sanitize(proposed_payload)
        else:
            payload = dict(name=name, description=description)

            # OSPF Interface Settings
            if ospf_interface_settings is not None:
                ospf_interface_pol = dict()
                interface_controls = dict()

                if ospf_interface_settings.get("advertise_subnet"):
                    interface_controls["advertiseSubnet"] = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("advertise_subnet"))

                if ospf_interface_settings.get("bfd"):
                    interface_controls["bfd"] = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("bfd"))

                if ospf_interface_settings.get("mtu_ignore"):
                    interface_controls["ignoreMtu"] = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("mtu_ignore"))

                if ospf_interface_settings.get("passive_participation"):
                    interface_controls["passiveParticipation"] = ENABLED_DISABLED_BOOLEAN_MAP.get(ospf_interface_settings.get("passive_participation"))

                if interface_controls:
                    ospf_interface_pol["ifControl"] = interface_controls

                if ospf_interface_settings.get("network_type"):
                    ospf_interface_pol["networkType"] = get_ospf_network_type(ospf_interface_settings.get("network_type"))

                if ospf_interface_settings.get("priority"):
                    ospf_interface_pol["prio"] = ospf_interface_settings.get("priority")

                if ospf_interface_settings.get("cost_of_interface"):
                    ospf_interface_pol["cost"] = ospf_interface_settings.get("cost_of_interface")

                if ospf_interface_settings.get("hello_interval"):
                    ospf_interface_pol["helloInterval"] = ospf_interface_settings.get("hello_interval")

                if ospf_interface_settings.get("dead_interval"):
                    ospf_interface_pol["deadInterval"] = ospf_interface_settings.get("dead_interval")

                if ospf_interface_settings.get("retransmit_interval"):
                    ospf_interface_pol["retransmitInterval"] = ospf_interface_settings.get("retransmit_interval")

                if ospf_interface_settings.get("transmit_delay"):
                    ospf_interface_pol["transmitDelay"] = ospf_interface_settings.get("transmit_delay")

                if ospf_interface_pol or ospf_interface_settings.get("state") == "enabled":
                    payload["ospfIntfPol"] = ospf_interface_pol

            # BFD MultiHop Settings
            if bfd_multi_hop_settings is not None:
                bfd_multi_hop_pol = dict()
                if bfd_multi_hop_settings.get("admin_state"):
                    bfd_multi_hop_pol["adminState"] = bfd_multi_hop_settings.get("admin_state")

                if bfd_multi_hop_settings.get("detection_multiplier"):
                    bfd_multi_hop_pol["detectionMultiplier"] = bfd_multi_hop_settings.get("detection_multiplier")

                if bfd_multi_hop_settings.get("min_receive_interval"):
                    bfd_multi_hop_pol["minRxInterval"] = bfd_multi_hop_settings.get("min_receive_interval")

                if bfd_multi_hop_settings.get("min_transmit_interval"):
                    bfd_multi_hop_pol["minTxInterval"] = bfd_multi_hop_settings.get("min_transmit_interval")

                if bfd_multi_hop_pol or bfd_multi_hop_settings.get("state") == "enabled":
                    payload["bfdMultiHopPol"] = bfd_multi_hop_pol

            # BFD Settings
            if bfd_settings is not None:
                bfd_settings_map = dict()

                if bfd_settings.get("admin_state"):
                    bfd_settings_map["adminState"] = bfd_settings.get("admin_state")

                if bfd_settings.get("detection_multiplier"):
                    bfd_settings_map["detectionMultiplier"] = bfd_settings.get("detection_multiplier")

                if bfd_settings.get("min_receive_interval"):
                    bfd_settings_map["minRxInterval"] = bfd_settings.get("min_receive_interval")

                if bfd_settings.get("min_transmit_interval"):
                    bfd_settings_map["minTxInterval"] = bfd_settings.get("min_transmit_interval")

                if bfd_settings.get("echo_receive_interval"):
                    bfd_settings_map["echoRxInterval"] = bfd_settings.get("echo_receive_interval")

                if bfd_settings.get("echo_admin_state"):
                    bfd_settings_map["echoAdminState"] = bfd_settings.get("echo_admin_state")

                if bfd_settings.get("interface_control"):
                    bfd_settings_map["ifControl"] = ENABLED_DISABLED_BOOLEAN_MAP.get(bfd_settings.get("interface_control"))

                if bfd_settings_map or bfd_settings.get("state") == "enabled":
                    payload["bfdPol"] = bfd_settings_map

            ops.append(dict(op="add", path=interface_routing_policy_path, value=copy.deepcopy(payload)))

            mso.sanitize(payload)
    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=interface_routing_policy_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_interface_routing_policy = mso_template.get_l3out_interface_routing_policy_object(uuid, name)
        if l3out_interface_routing_policy:
            mso.existing = l3out_interface_routing_policy.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_ospf_network_type(network_type):
    return "pointToPoint" if network_type == "point_to_point" else network_type


if __name__ == "__main__":
    main()
