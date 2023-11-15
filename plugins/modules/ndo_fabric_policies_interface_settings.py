#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template
short_description: Manage templates in schemas
description:
- Manage templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  tenant:
    description:
    - The tenant used for this template.
    type: str
    required: true
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  schema_description:
    description:
    - The description of Schema is supported on versions of MSO that are 3.3 or greater.
    type: str
  template_description:
    description:
    - The description of template is supported on versions of MSO that are 3.3 or greater.
    type: str
  template:
    description:
    - The name of the template.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
 template_type:
    description:
     - Deployment Mode. Use stretched-template for Multi-Site or non-stretched-template for Autonomous
     type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API this module creates schemas when needed, and removes them when the last template has been removed.
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_site
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new template to a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: present
  delegate_to: localhost

- name: Remove a template from a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: absent
  delegate_to: localhost

- name: Query a template
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all templates
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, diff_dicts


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        interface=dict(type="str", aliases=["domain_name", "domain_profile", "name"]),
        description=dict(type="str", aliases=["descr"]),
        template=dict(type="str", required=True),
        interface_type=dict(type="str", choices=["physical", "port-channel"], required=True),
        speed=dict(type="str", choices=["inherit", "100M", "1G", "10G", "25G", "40G", "50G", "100G", "400G"], default="inherit"),
        auto_negotiation=dict(type="str", choices=["on", "off", "on-enforce"], default="on"),
        vlan_scope=dict(type="str", choices=["global", "port_local"], default="global"),
        cdp=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        lldp_transmit=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
        lldp_receive=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
        domain=dict(type="str", aliases=["domain_name", "domain_profile",]),
        debounce=dict(type="int", default=100),
        bring_up_delay=dict(type="int", default=0),
        bpdu_filter=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        bpdu_guard=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        mcp=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
        mcp_strict_mode=dict(type="str", choices=["on", "off"], default="off"),
        port_channel_mode=dict(type="str", choices=["active", "passive", "mac-pin" , "mac-pin-nicload", "off", "explicit-failover"]),
        port_channel_control=dict(type="list", elements="str", choices=["fast-sel-hot-stdby", "graceful-conv", "load-defer", "susp-individual", "symmetric-hash"], default=["fast-sel-hot-stdby", "graceful-conv", "susp-individual" ]),
        min_links=dict(type="int", default=1),
        max_links=dict(type="int", default=16),
        llfc_transmit=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        llfc_receive=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        pfc=dict(type="str", choices=["on", "off", "auto"], default="auto"),
        qinq=dict(type="str", choices=["disabled", "corePort", "edgePort", "doubleQtagPort"], default="disabled"),
        reflective_relay=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
        fec=dict(type="str", choices=["inherit", "cl74-fc-fec", "cl91-rs-fec", "cons16-rs-fec", "ieee-rs-fec", "kp-fec", "disable-fec"], default="inherit"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        initialDelayTime=dict(type="int", default=180),
        txFreq=dict(type="int", default=2),
        txFreqMsec=dict(type="int", default=0),
        gracePeriod=dict(type="int", default=3),
        gracePeriodMsec=dict(type="int", default=0),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["template"]],
            ["state", "present", ["template"]],
        ],
    )

    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    state = module.params.get("state")
    interface = module.params.get("interface")
    template = module.params.get("template")
    description = module.params.get("description")
    interface_type = module.params.get("interface_type")
    speed = module.params.get("speed")
    auto_negotiation = module.params.get("auto_negotiation")
    vlan_scope = module.params.get("vlan_scope")
    cdp = module.params.get("cdp")
    lldp_transmit = module.params.get("lldp_transmit")
    lldp_receive = module.params.get("lldp_receive")
    debounce = module.params.get("debounce")
    bring_up_delay = module.params.get("bring_up_delay")
    bpdu_filter = module.params.get("bpdu_filter")
    bpdu_guard = module.params.get("bpdu_guard")
    mcp = module.params.get("mcp")
    mcp_strict_mode = module.params.get("mcp_strict_mode")
    port_channel_mode = module.params.get("port_channel_mode")
    port_channel_control = module.params.get("port_channel_control")
    min_links = module.params.get("min_links")
    max_links = module.params.get("max_links")
    llfc_transmit = module.params.get("llfc_transmit")
    llfc_receive = module.params.get("llfc_transmit")
    pfc = module.params.get("pfc")
    qinq = module.params.get("qinq")
    reflective_relay = module.params.get("reflective_relay")
    fec = module.params.get("fec")
    initialDelayTime = module.params.get("initialDelayTime")
    txFreq = module.params.get("txFreq")
    txFreqMsec = module.params.get("txFreqMsec")
    gracePeriod = module.params.get("gracePeriod")
    gracePeriodMsec = module.params.get("gracePeriodMsec")


    mso = MSOModule(module)

    template_type = "fabricPolicy"


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}

    if templates:
        for temp in templates:
            if temp['templateName'] == template and temp['templateType'] == template_type:
                template_id = temp['templateId']
    else:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))


    ##get the template

    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")


    interface_exist = False

    # try to find if the interface exist
    if 'template' in mso.existing['fabricPolicyTemplate'] and 'interfacePolicyGroups' in mso.existing['fabricPolicyTemplate']['template']:
        for count, d in enumerate(mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups']):
            if d['name'] == interface:
                interface_exist = True
                interface_index = count



    if state == "query":
        if not mso.existing:
            if template:
                mso.fail_json(msg="Template '{0}' not found".format(template))
            else:
                mso.existing = []
        mso.exit_json()

    template_path = f"templates/{template_id}"

    mso.previous = mso.existing
    if state == "absent":
        mso.proposed = mso.sent = {}
        #case interface exist and need be deleted
        if interface_exist:
            del mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]
            if len(mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups']) == 0:
                del mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups']
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        new_interface = {
            "name": interface,
            "type": interface_type,
            "cdp": {
                "adminState": cdp
            },
            "lldp":
                {
                    "receiveState": lldp_receive,
                    "transmitState": lldp_transmit
                },
            "llfc":
                {
                    "receiveState": llfc_receive,
                    "transmitState": llfc_transmit
                },
            "pfc":
                {
                    "adminState": pfc,
                },
            "l2Interface":
                {
                    "qinq": qinq,
                    "reflectiveRelay": reflective_relay,
                    "vlanScope": vlan_scope
                },
            "stp":
                {
                    "bpduFilterEnabled": bpdu_filter,
                    "bpduGuardEnabled": bpdu_guard
                },
            "linkLevel":
                {
                    "speed": speed,
                    "autoNegotiation": auto_negotiation,
                    "bringUpDelay": bring_up_delay,
                    "debounceInterval": debounce,
                    "fec": fec
                },
            "mcp":
                {
                    "adminState": mcp,
                    "mcpMode": mcp_strict_mode,
                    "initialDelayTime": initialDelayTime,
                    "txFreq": txFreq,
                    "txFreqMsec": txFreqMsec,
                    "gracePeriod": gracePeriod,
                    "gracePeriodMsec": gracePeriodMsec
                },
        }
        if description:
            new_interface.update(
                {
                    "description": description
                }
            )
        else:
            new_interface.update(
                {
                    "description": ""
                }
            )
        if interface_type == 'physical':
            new_interface.update(
                {
                    "portChannelPolicy":
                        {
                            "minLinks": 0,
                            "maxLinks": 0
                        }
                }
            )
        else:
            new_interface.update(
                {
                    "portChannelPolicy":
                        {
                            "mode": port_channel_mode,
                            "control": port_channel_control,
                            "minLinks": min_links,
                            "maxLinks": max_links,
                        }
                }
            )
        #interface doesn't exitst, need be created
        if not interface_exist:
            if not 'interfacePolicyGroups' in mso.existing['fabricPolicyTemplate']['template']:
                mso.existing['fabricPolicyTemplate']['template'].update({'interfacePolicyGroups': []})
            mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'].append(new_interface)

            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        else:
            #domain exist check if need be updated
            current = mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index].copy()
            current.pop('uuid')
            diff = diff_dicts(current, new_interface)
            if diff:
                for item in diff:
                    mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index][item] = diff[item][1]
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed


    mso.exit_json()


if __name__ == "__main__":
    main()
