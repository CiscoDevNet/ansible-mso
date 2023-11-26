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
        l3out=dict(type="str", aliases=["name"], required=True),
        template=dict(type="str", required=True),
        description=dict(type="str", aliases=["descr"]),
        vrf=dict(type="dict", options=mso_reference_spec()),
        l3out_domain=dict(type="str", required=True),
        import_route_control=dict(type="bool", default=False),
        enable_bgp=dict(type="bool", default=False),
        enable_ospf=dict(type="bool", default=False),
        ospf_area_id=dict(type="int", default=0),
        ospf_area_type=dict(type="str", choices=["regular", "stub", "nssa"], default="regular"),
        ospf_area_cost=dict(type="int", default=1),
        inbound_route_map=dict(type="str"),
        inbound_route_map_template=dict(type="str"),
        outbound_route_map=dict(type="str"),
        outbound_route_map_template=dict(type="str"),
        enable_pim=dict(type="bool", default=False),
        enable_pimv6=dict(type="bool", default=False),
        originate_default_route=dict(type="bool", default=False),
        originate_default_route_type=dict(type="str", choices=["default_only","default_in_addition"], default="default_only"),
        target_dscp=dict(type="str", choices=["unspecified","CS0","CS1","AF11","AF12","AF13","CS2","AF21","AF22","AF23","CS3","AF31","AF32","AF33","CS4","AF41","AF42","AF43","VA","CS5","EF","CS6","CS7"], default="unspecified"),
        state = dict(type="str", default="present", choices=["absent", "present", "query"])
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
    description = module.params.get("description")
    l3out = module.params.get("l3out")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf.get("template").replace(" ", "")
    l3out_domain = module.params.get("l3out_domain")
    import_route_control = module.params.get("import_route_control")
    enable_bgp = module.params.get("enable_bgp")
    enable_ospf = module.params.get("enable_ospf")
    ospf_area_id = module.params.get("ospf_area_id")
    ospf_area_type = module.params.get("ospf_area_type")
    ospf_area_cost = module.params.get("ospf_area_cost")
    inbound_route_map = module.params.get("inbound_route_map")
    inbound_route_map_template = module.params.get("inbound_route_map_template")
    outbound_route_map = module.params.get("outbound_route_map")
    outbound_route_map_template = module.params.get("outbound_route_map_template")
    enable_pim = module.params.get("enable_pim")
    enable_pimv6 = module.params.get("enable_pimv6")
    originate_default_route = module.params.get("originate_default_route")
    originate_default_route_type = module.params.get("originate_default_route_type")
    target_dscp = module.params.get("target_dscp")



    mso = MSOModule(module)

    template_type = "l3out"


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}

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
        if l3out_exist:
            del mso.existing['l3outTemplate']['l3outs'][l3out_index]
            if len(mso.existing['l3outTemplate']['l3outs']) == 0:
                del mso.existing['l3outTemplate']['l3outs']

            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        vrf_schema_id, vrf_schema_path, vrf_schema_obj = mso.query_schema(vrf['schema'])
        # Get template
        vrf_templates = [t.get("name") for t in vrf_schema_obj.get("templates")]
        if vrf['template'] not in vrf_templates:
            mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(vrf['template'], ", ".join(vrf_templates)))
        template_idx = vrf_templates.index(vrf['template'])

        #get vrfs
        vrfs = [v.get("name") for v in vrf_schema_obj.get("templates")[template_idx]["vrfs"]]
        
        if vrf['name'] is not None and vrf['name'] in vrfs:
            vrf_idx = vrfs.index(vrf['name'])
            vrf_dict = vrf_schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]

        


        new_l3out = {
            "name": l3out,
            "vrfRef": vrf_dict['uuid'],
            "importRouteControl": import_route_control,
            "targetDscp": target_dscp,
            "tagAnnotations": [],
            "pim": enable_pim,
            "routingProtocol": "none"
        }
        if description:
            new_l3out['description'] = description
        if l3out_domain:
            new_l3out['l3domain']= l3out_domain
        if enable_bgp and enable_ospf:
            new_l3out['routingProtocol'] = "bgpOspf"
        elif enable_bgp:
            new_l3out['routingProtocol'] = "bgp"
        elif enable_ospf:
            new_l3out['routingProtocol'] = "ospf"

        if enable_ospf:
            area_id = int_to_ipv4(ospf_area_id)
            if area_id == "0.0.0.0" and ospf_area_type != 'regular':
                mso.fail_json(msg="OSPF area 0 only can be regular")
            new_l3out.update(
                {
                    "ospfAreaConfig" : {
                        "id": area_id,
                        "cost": ospf_area_cost,
                        "areaType": ospf_area_type,
                        "control":
                            {
                                "redistribute": True,
                                "originate": True,
                                "suppressFA": False
                            }
                    }
                }
            )
        if originate_default_route:
            if originate_default_route_type == 'default_only':
                default_type = 'only'
            else:
                default_type = 'inAddition'

            new_l3out.update(
                {
                    "defaultRouteLeak":
                        {
                            "originateDefaultRoute": default_type,
                            "always": False
                        },
                }
            )
        if inbound_route_map and new_l3out['routingProtocol'] != "none":
            template_id = get_template_id(template_name=inbound_route_map_template, template_type='tenantPolicy', template_dict=templates)
            rm_template = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")
            inbound_route_map_uuid = get_route_map_uuid(route_map=inbound_route_map, template_dict=rm_template)
            if inbound_route_map_uuid:
                new_l3out['importRouteMapRef'] = inbound_route_map_uuid
            else:
                mso.fail_json(msg=f"Route-map {inbound_route_map} not found")
                
        if outbound_route_map and new_l3out['routingProtocol'] != "none":
            template_id = get_template_id(template_name=outbound_route_map_template, template_type='tenantPolicy', template_dict=templates)
            rm_template = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")
            outbound_route_map_uuid = get_route_map_uuid(route_map=inbound_route_map, template_dict=rm_template)
            if inbound_route_map_uuid:
                new_l3out['exportRouteMapRef'] = outbound_route_map_uuid
            else:
                mso.fail_json(msg=f"Route-map {outbound_route_map} not found")





        if not l3out_exist:
            if 'l3outs' not in mso.existing['l3outTemplate']:
                mso.existing['l3outTemplate'].update({'l3outs' : []})

            mso.existing['l3outTemplate']['l3outs'].append(new_l3out)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        else:
            # check if need be updated
            current = mso.existing['l3outTemplate']['l3outs'][l3out_index].copy()
            diff = diff_dicts(new_l3out,current,exclude_key="interfaceGroups,nodes,subInterfaces,interfaces,svi,floatingSviInterfaces,sviInterfaces")
            if diff:
                mso.existing['l3outTemplate']['l3outs'][l3out_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed





    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
