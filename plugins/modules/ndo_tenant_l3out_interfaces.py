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
        node1_router_id=dict(type="str", required=True),
        node1_router_id_as_loopback=dict(type="bool", default=False),
        node2=dict(type="str"),
        node2_router_id=dict(type="str"),
        node2_router_id_as_loopback=dict(type="bool", default=False),
        pod_id=dict(type="str", required=True),
        path=dict(type="str", required=True),
        vlan_encap_id=dict(type="int"),
        trunk_mode=dict(type="str", choices=["trunk","access8021p","access"], default="trunk"),
        ipv4_addr_node1=dict(type="str"),
        ipv4_addr_node2=dict(type="str"),
        ipv4_secondary_ip=dict(type="str"),
        ipv6_addr_node1=dict(type="str",),
        ipv6_addr_node2=dict(type="str"),
        ipv6_secondary_ip=dict(type="str"),
        mac=dict(type="str", default="00:22:BD:F8:19:FF"),
        mtu=dict(type="str", default="inherit"),
        autostate=dict(type="str", choices=["enabled","disabled"], default="disabled"),
        interface_group_policy=dict(type="str"),
        target_dscp=dict(type="str", default="unspecified"),
        ipv6_dad=dict(type="str", choices=["enabled","disabled"], default="disabled"),
        ipv6_link_local_node1=dict(type="str"),
        ipv6_link_local_node2=dict(type="str"),
        secondary_nd_ra_prefix=dict(type="bool", default=False),
        secondary_ipv6_dad=dict(type="str", choices=["enabled","disabled"], default="enabled"),
        encap_scope=dict(type="str", choices=["local","vrf"], default="local"),
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
    node1_router_id = module.params.get("node1_router_id")
    node1_router_id_as_loopback =module.params.get("node1_router_id_as_loopback")
    node2 = module.params.get("node2")
    node2_router_id = module.params.get("node2_router_id")
    node2_router_id_as_loopback = module.params.get("node2_router_id_as_loopback")
    pod_id = module.params.get("pod_id")
    interface_path = module.params.get("path")
    vlan_encap_id = module.params.get("vlan_encap_id")
    trunk_mode = module.params.get("trunk_mode")
    ipv4_addr_node1 = module.params.get("ipv4_addr_node1")
    ipv4_addr_node2 = module.params.get("ipv4_addr_node2")
    ipv4_secondary_ip = module.params.get("ipv4_secondary_ip")
    ipv6_addr_node1 = module.params.get("ipv6_addr_node1")
    ipv6_addr_node2 = module.params.get("ipv6_addr_node2")
    ipv6_secondary_ip = module.params.get("ipv6_secondary_ip")
    ipv6_link_local_node1= module.params.get("ipv6_link_local_node1")
    ipv6_link_local_node2= module.params.get("ipv6_link_local_node2")
    mtu = module.params.get("mtu")
    mac =  module.params.get("mac")
    autostate = module.params.get("autostate")
    interface_group_policy = module.params.get("interface_group_policy")
    target_dscp = module.params.get("target_dscp")
    ipv6_dad = module.params.get("ipv6_dad")
    secondary_nd_ra_prefix = module.params.get("secondary_nd_ra_prefix")
    secondary_ipv6_dad = module.params.get("secondary_ipv6_dad")
    encap_scope =  module.params.get("encap_scope")




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
        
    if not (ipv4_addr_node1 or ipv6_addr_node1):
        mso.fail_json(msg="IP/IPV6 address ID not not found")
    
    if path_type == 'vpc' and not ((ipv4_addr_node1 and ipv4_addr_node2) or (ipv6_addr_node1 and ipv6_addr_node2)):
        mso.fail_json(msg="VPC IP/IPV6 address ID not not found ")


        
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


    # try to find if the interface Groups exist
    group_policy_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups']):
            if e['name'] == interface_group_policy:
                group_policy_exist = True
                group_policy_index = count
    except:
        pass
    


    #try to find if the node exist
    node1_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes']):
            if e['nodeID'] == node1:
                node1_exist = True
                node1_index = count
    except:
        pass
    

    #try to find if the interface exit
    interface_exist = False
    if node1_exist:
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
        
    
    if path_type == 'vpc':
        node2_exist = False
        try:
            for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes']):
                if e['nodeID'] == node2:
                    node2_exist = True
                    node2_index = count
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
        if interface_exist:
            nodes_to_check = str(mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]['nodeID']).split(',')
            del mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index]
            
            for int_type in interface_type_dict:
                try:
                    for interface in mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[int_type]]:
                        node_ids = str(interface['nodeID']).split(',')
                        for node in node_ids:
                            if node in nodes_to_check:
                                node_idx = nodes_to_check.index(node)
                                nodes_to_check[node_idx] = None
                except:
                    pass
            
            if len(mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[int_type]]) == 0:
                del mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[int_type]]

            
            if nodes_to_check[0]:
                del mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index]
            
            if path_type == 'vpc' and nodes_to_check[1]:
                #update node2 position
                node2_exist = False
                try:
                    for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes']):
                        if e['nodeID'] == node2:
                            node2_exist = True
                            node2_index = count
                except:
                    pass
                del mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node2_index]

            if len(mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes']) == 0:
                del mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes']
                    

            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        new_node1 = {
            "group": "",
            "podID": pod_id,
            "nodeID": node1,
            "routerID": node1_router_id,
            "useRouteIDAsLoopback": node1_router_id_as_loopback
        }
        new_interface = {
            "group": "",
            "pathType": path_type,
            "podID": pod_id,
            "nodeID": node1,
            "path": interface_path,
            "addresses":
                {
                    "ipV6DAD": ipv6_dad,
                    "secondary": []
                },
            "mac": mac,
            "mtu": mtu,
            "targetDscp": target_dscp
        }
        if ipv4_addr_node1:
            new_interface['addresses']['primaryV4'] = ipv4_addr_node1
        if ipv6_addr_node1:
            new_interface['addresses']['primaryV6'] = ipv6_addr_node1
        if ipv6_link_local_node1:
            new_interface['addresses']['linkLocalV6'] = ipv6_link_local_node1
        if ipv4_secondary_ip:
            new_secondary={
                "address": ipv4_secondary_ip,
                "dhcpRelay": False,
                "v6RAPrefix": False,
                "ipV6DAD": "enabled"
            }
            new_interface['addresses']['secondary'].append(new_secondary)
        if ipv6_secondary_ip:
            new_secondary={
                "address": ipv6_secondary_ip,
                "dhcpRelay": False,
                "v6RAPrefix": secondary_nd_ra_prefix,
                "ipV6DAD": secondary_ipv6_dad
            }
            new_interface['addresses']['secondary'].append(new_secondary)
        if interface_group_policy:
            new_interface['group']= interface_group_policy
        if interface_type != "routed":
            new_interface.update(
                {
                "encap":
                    {
                        "encapType": "vlan",
                        "value": vlan_encap_id
                    }
                }
            )

        if interface_type == "svi":
            new_interface.update(
                {
                    "svi":
                        {
                            "encapScope": encap_scope,
                            "autostate": autostate,
                            "mode":  trunk_mode
                        },
                }
            )

        if len(new_interface['addresses']['secondary']) == 0:
            new_interface['addresses'].pop('secondary')

        if path_type =='vpc':
            ####special case for VPC
            new_node2 = {
                "group": "",
                "podID": pod_id,
                "nodeID": node2,
                "routerID": node2_router_id,
                "useRouteIDAsLoopback": node2_router_id_as_loopback
            }
            new_interface['nodeID']=node1+","+node2
            new_interface.update(
                {
                    "sideBAddresses":
                        {
                            "ipV6DAD": "disabled",
                            "secondary": []
                        },
                    
                }
            )
            if ipv4_addr_node2:
                new_interface['sideBAddresses']['primaryV4'] = ipv4_addr_node2
            if ipv6_addr_node2:
                new_interface['sideBAddresses']['primaryV6'] = ipv6_addr_node2
            if ipv6_link_local_node1:
                new_interface['sideBAddresses']['linkLocalV6'] = ipv6_link_local_node2
            if ipv4_secondary_ip:
                new_secondary = {
                    "address": ipv4_secondary_ip,
                    "dhcpRelay": False,
                    "v6RAPrefix": False,
                    "ipV6DAD": "enabled"
                }
                new_interface['sideBAddresses']['secondary'].append(new_secondary)
            if ipv6_secondary_ip:
                new_secondary = {
                    "address": ipv6_secondary_ip,
                    "dhcpRelay": False,
                    "v6RAPrefix": secondary_nd_ra_prefix,
                    "ipV6DAD": secondary_ipv6_dad
                }
                new_interface['sideBAddresses']['secondary'].append(new_secondary)

            if len(new_interface['sideBAddresses']['secondary']) == 0:
                new_interface['sideBAddresses'].pop('secondary')
            
            
            if not node1_exist or not node2_exist:
                #case one of the nodes doesn't exist, added the missing node and the interface 

                if 'nodes' not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update({"nodes": []})
                
                if not node1_exist:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'].append(new_node1)
                
                if not node2_exist:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'].append(new_node2)

                if interface_type_dict[interface_type] not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update({interface_type_dict[interface_type]: []})

                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]].append(new_interface)

                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed
                
            elif not interface_exist:
                # interface doesn't exist 
                if interface_type_dict[interface_type] not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update(
                        {interface_type_dict[interface_type]: []})

                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]].append(
                    new_interface)

                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed

            else:
                current_node1 = mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index].copy()
                diff_node1 = diff_dicts(new_node1, current_node1)
                
                current_node2 = mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index].copy()
                diff_node2 = diff_dicts(new_node1, current_node2)
                

                current_interface = mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index].copy()
                diff_interface = diff_dicts(new_interface, current_interface, exclude_key="bgpPeers")

                if diff_interface or diff_node1 or diff_node2:
                    if diff_node1:
                        mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index] = update_payload(diff=diff_node1, payload=current_node1)
                    if diff_node2:
                        mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node2_index_] = update_payload(diff=diff_node1, payload=current_node2)

                    if diff_interface:
                        mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index] = update_payload(diff=diff_interface, payload=current_interface)
                    if not module.check_mode:
                        mso.request(template_path, method="PUT", data=mso.existing)
                    mso.existing = mso.proposed

            
                
        else:
            if not node1_exist:
                ###interface and node doesnt exist
                if 'nodes' not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update({"nodes": []})
    
                mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'].append(new_node1)
    
                if interface_type_dict[interface_type] not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update({interface_type_dict[interface_type] : []})
    
                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]].append(new_interface)
    
                
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed
            elif not interface_exist:
                #interface doesn't exist 
                if interface_type_dict[interface_type] not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                    mso.existing['l3outTemplate']['l3outs'][l3out_index].update({interface_type_dict[interface_type] : []})
    
                mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]].append(new_interface)
                
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed
            else:
                # check if need be updated
                current_node = mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index].copy()
                diff_node = diff_dicts(new_node1,current_node,exclude_key="bgpPeers")
                
                
                current_interface = mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index].copy()
                diff_interface = diff_dicts(new_interface,current_interface,exclude_key="bgpPeers")
                
                if diff_interface or diff_node:
                    if diff_node:
                        mso.existing['l3outTemplate']['l3outs'][l3out_index]['nodes'][node1_index] = update_payload(diff=diff_node, payload=current_node)
                    if diff_interface:
                        mso.existing['l3outTemplate']['l3outs'][l3out_index][interface_type_dict[interface_type]][interface_index] = update_payload(diff=diff_interface, payload=current_interface)
                    if not module.check_mode:
                        mso.request(template_path, method="PUT", data=mso.existing)
                    mso.existing = mso.proposed

    

    mso.exit_json()


if __name__ == "__main__":
    main()
