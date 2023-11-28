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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, diff_dicts, update_payload, int_to_ipv4, get_route_map_uuid, mso_reference_spec, get_template_id


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        l3out=dict(type="str", required=True),
        template=dict(type="str", required=True),
        interface_type=dict(type="str", choices=["routed_sub", "routed", "svi"], required=True),
        path_type=dict(type="str", choices=["port","vpc","pc"], required=True),
        node1=dict(type="str", required=True),
        node2=dict(type="str"),
        pod_id=dict(type="str", required=True),
        path=dict(type="str", required=True),
        vlan_encap_id=dict(type="int"),
        bgp_peer_ipv4=dict(type="str"),
        bgp_peer_ipv6=dict(type="str"),
        bgp_peer_as=dict(type="int"),
        use_bfd=dict(type="bool", default=False),
        bgp_password=dict(type="str"),
        inbound_route_map=dict(type="str"),
        inbound_route_map_template=dict(type="str"),
        outbound_route_map=dict(type="str"),
        outbound_route_map_template=dict(type="str"),
        local_as=dict(type="int"),
        local_as_options=dict(type="str", choices=["none","no-prepend","dual-as","replace-as"], default="none"),
        allow_self_as=dict(type="bool", default=False),
        allow_self_as_count=dict(type="int", default=3),
        private_as_control=dict(type="str", choices=["remove_private_as","remove_all_private_as", "replace_private_as_with_local_as"]),
        address_type_controls=dict(type="list", elements="str", choices=["af-ucast", "af-mcast"], default=['af-ucast']),
        disable_connected_check=dict(type="bool", default=False),
        as_override=dict(type="bool", default=False),
        disable_peer_as_check=dict(type="bool", default=False),
        next_hop_self=dict(type="bool", default=False),
        send_community=dict(type="bool", default=False),
        send_extended_community=dict(type="bool", default=False),
        send_domain_path=dict(type="bool", default=False),
        admin_state=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
        ebgp_multihop_ttl=dict(type="int", default=1),
        weight=dict(type="int"),
        site_of_origin=dict(type="str"),
        bgp_peer_prefix_policy=dict(type="str"),
        update_password=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["absent", "present", "query"])
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
    l3out = module.params.get("l3out")
    interface_type = module.params.get("interface_type")
    path_type = module.params.get("path_type")
    node1 = module.params.get("node1")
    node2 = module.params.get("node2")
    pod_id = module.params.get("pod_id")
    interface_path = module.params.get("path")
    vlan_encap_id = module.params.get("vlan_encap_id")
    bgp_peer_ipv4 = module.params.get("bgp_peer_ipv4")
    bgp_peer_ipv6 = module.params.get("bgp_peer_ipv6")
    bgp_peer_as = module.params.get("bgp_peer_as")
    use_bfd = module.params.get("use_bfd")
    bgp_password = module.params.get("bgp_password")
    inbound_route_map = module.params.get("inbound_route_map")
    inbound_route_map_template = module.params.get("inbound_route_map_template")
    outbound_route_map = module.params.get("outbound_route_map")
    outbound_route_map_template = module.params.get("outbound_route_map_template")
    local_as = module.params.get("local_as")
    local_as_options = module.params.get("local_as_options")
    allow_self_as = module.params.get("allow_self_as")
    allow_self_as_count = module.params.get("allow_self_as_count")
    private_as_control = module.params.get("private_as_control")
    address_type_controls = module.params.get("address_type_controls")
    disable_connected_check =module.params.get("disable_connected_check")
    as_override = module.params.get("as_override")
    disable_peer_as_check = module.params.get("disable_peer_as_check")
    next_hop_self = module.params.get("next_hop_self")
    send_community = module.params.get("send_community")
    send_extended_community =module.params.get("send_extended_community")
    send_domain_path = module.params.get("send_domain_path")
    admin_state = module.params.get("admin_state")
    ebgp_multihop_ttl = module.params.get("ebgp_multihop_ttl")
    weight = module.params.get("weight")
    site_of_origin = module.params.get("site_of_origin")
    bgp_peer_prefix_policy = module.params.get("bgp_peer_prefix_policy")
    update_password = module.params.get("update_password")


    mso = MSOModule(module)

    template_type = "l3out"

    interface_type_dict= {
        "routed_sub": "subInterfaces",
        "routed": "interfaces",
        "svi": "sviInterfaces"
    }

    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")

    mso.existing = {}


    if interface_type != 'routed' and not vlan_encap_id:
        mso.fail_json(msg="Vlan ID not not found")

    if not (bgp_peer_ipv4 or bgp_peer_ipv6):
        mso.fail_json(msg="At least one Peer must exist")

        
    template_id = get_template_id(template_name=template, template_type=template_type, template_dict=templates)

    if not template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))
    
    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")


    # try to find if the l3out exist
    l3out_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs']):
            if e['name'] == l3out:
                l3out_exist = True
                l3out_index = count
    except:
        pass

    if not l3out_exist:
        mso.fail_json(msg="L3out '{l3out}' not found".format(l3out=l3out))

    

    #try to find if the interface exit
    interface_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]]):
            if path_type == 'vpc':
                if e['nodeID'] == node1+','+node2 and e['path'] == interface_path:
                    if interface_type != 'routed':
                        if e['encap']['value'] == vlan_encap_id:
                            interface_exist = True
                            interface_index = count

            else:
                if e['nodeID'] == node1 and e['path'] == interface_path:
                    if interface_type != 'routed':
                        if e['encap']['value'] == vlan_encap_id:
                            interface_exist = True
                            interface_index = count
                    else:
                        interface_exist = True
                        interface_index = count
    except:
        pass

    if not interface_exist:
        mso.fail_json(msg="Interface not found")


    #try to find the bgp peer
    bgp_peer_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers']):
            if e['peerAddressV4'] == bgp_peer_ipv4 or e['peerAddressV6'] == bgp_peer_ipv6 :
                bgp_peer_exist = True
                bgp_peer_index = count
    except:
        pass


    

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
        if bgp_peer_exist:
            del mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers'][bgp_peer_index]
            if len(mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers']) == 0:
                del mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers']
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        new_bgp_peer = {
            "adminState": admin_state,
            "authEnabled": False,
            "allowedSelfASCount": allow_self_as_count,
            "ebpgMultiHopTTL": ebgp_multihop_ttl,
            "localAsnConfig": local_as_options,
            "bgpControls":
                {
                    "allowSelfAS": allow_self_as,
                    "asOverride": as_override,
                    "disablePeerASCheck": disable_peer_as_check,
                    "nextHopSelf": next_hop_self,
                    "sendCommunity": send_community,
                    "sendExtendedCommunity": send_extended_community,
                    "sendDomainPath": send_domain_path
                },
            "peerControls":
                {
                    "bfd": use_bfd,
                    "disableConnectedCheck": disable_connected_check
                },
            "privateASControls":
                {
                    "removeAll": False,
                    "removeExclusive": False,
                    "replaceWithLocalAS": False
                },
            "addressTypeControls":
                {
                    "afMast": False,
                    "afUcast": False
                },

        }
        if bgp_peer_as:
            new_bgp_peer['peerAsn'] = bgp_peer_as
        if local_as:
            new_bgp_peer['localAsn'] = local_as
        if bgp_peer_ipv4:
            new_bgp_peer['peerAddressV4'] = bgp_peer_ipv4
        if bgp_peer_ipv6:
            new_bgp_peer['peerAddressV6'] = bgp_peer_ipv6
        if 'af-ucast' in address_type_controls:
            new_bgp_peer['addressTypeControls']['afUcast'] = True
        if 'af-mcast' in address_type_controls:
            new_bgp_peer['addressTypeControls']['afMast'] = True
        if private_as_control:
            if private_as_control == "remove_private_as":
                new_bgp_peer['privateASControls']['removeExclusive'] = True
            elif private_as_control == "remove_all_private_as":
                new_bgp_peer['privateASControls']['removeExclusive'] = True
                new_bgp_peer['privateASControls']['removeAll'] = True
            else:
                new_bgp_peer['privateASControls']['removeExclusive'] = True
                new_bgp_peer['privateASControls']['removeAll'] = True
                new_bgp_peer['privateASControls']['replaceWithLocalAS'] = True
        if weight:
            new_bgp_peer['weight'] = weight
        if site_of_origin:
            new_bgp_peer['siteOfOrigin'] = site_of_origin
        if bgp_password:
            new_bgp_peer.update(
                {
                    "authEnabled": True,
                    "password":
                        {
                            "value": bgp_password
                        },
                }
            )

        if inbound_route_map:
            template_id = get_template_id(template_name=inbound_route_map_template, template_type='tenantPolicy',template_dict=templates)
            rm_template = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")
            inbound_route_map_uuid = get_route_map_uuid(route_map=inbound_route_map, template_dict=rm_template)
            if inbound_route_map_uuid:
                new_bgp_peer['importRouteMapRef'] = inbound_route_map_uuid
            else:
                mso.fail_json(msg=f"Route-map {inbound_route_map} not found")

        if outbound_route_map:
            template_id = get_template_id(template_name=outbound_route_map_template, template_type='tenantPolicy', template_dict=templates)
            rm_template = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")
            outbound_route_map_uuid = get_route_map_uuid(route_map=outbound_route_map, template_dict=rm_template)
            if outbound_route_map_uuid:
                new_bgp_peer['exportRouteMapRef'] = outbound_route_map_uuid
            else:
                mso.fail_json(msg=f"Route-map {outbound_route_map} not found")
                            
        if not bgp_peer_exist:
            ### bgp peer doesnt exist
            if 'bgpPeers' not in mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]:
                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index].update({"bgpPeers": []})

            mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers'].append(new_bgp_peer)


            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed

        else:
            # check if need be updated
            current = mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers'][bgp_peer_index].copy()
            if update_password:
                diff = diff_dicts(new_bgp_peer,current)
            else:
                diff = diff_dicts(new_bgp_peer,current,exclude_key="password,authEnabled")
            if diff:
           
                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['bgpPeers'][bgp_peer_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed

    

    mso.exit_json()


if __name__ == "__main__":
    main()
