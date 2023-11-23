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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, diff_dicts, update_payload


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        route_map=dict(type="str", required=True),
        template=dict(type="str", required=True),
        context_name=dict(type="str", required=True),
        set_community=dict(type="str"),
        set_community_criteria=dict(type="str", choices=["append", "none", "replace"]),
        set_route_tag=dict(type="int"),
        set_dampening=dict(type="bool", default=False),
        half_life=dict(type="int", default=15),
        re_use_limit=dict(type="int", default=750),
        supress_limit=dict(type="int", default=2000),
        max_suppress_time=dict(type="int", default=60),
        set_weight=dict(type="int"),
        set_next_hop=dict(type="str"),
        set_preference=dict(type="int"),
        set_metric=dict(type="int"),
        set_next_hop_propagate=dict(type="bool", default=False),
        set_multipath=dict(type="bool", default=False),
        set_metric_type=dict(type="str", choices=["ospf-type1", "ospf-type2"]),
        set_as_path_criteria=dict(type="str", choices=["prepend", "prepend_last_as"]),
        set_as=dict(type="int"),
        set_as_order=dict(type="int"),
        set_as_path_count=dict(type="int"),
        set_additional_community=dict(type="str"),
        set_additional_community_criteria=dict(type="str", choices=["append"]),
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
    route_map = module.params.get("route_map")
    context_name = module.params.get("context_name")
    action = module.params.get("action")
    order = module.params.get("order")
    set_community = module.params.get("set_community")
    set_community_criteria = module.params.get("set_community_criteria")
    set_route_tag = module.params.get("set_route_tag")
    set_dampening = module.params.get("set_dampening")
    half_life = module.params.get("half_life")
    re_use_limit = module.params.get("re_use_limit")
    supress_limit = module.params.get("supress_limit")
    max_suppress_time = module.params.get("max_suppress_time")
    set_weight = module.params.get("set_weight")
    set_next_hop = module.params.get("set_next_hop")
    set_preference = module.params.get("set_preference")
    set_metric = module.params.get("set_metric")
    set_next_hop_propagate = module.params.get("set_next_hop_propagate")
    set_multipath = module.params.get("set_multipath")
    set_metric_type = module.params.get("set_metric_type")
    set_as_path_criteria = module.params.get("set_as_path_criteria")
    set_as = module.params.get("set_as")
    set_as_order = module.params.get("set_as_order")
    set_as_path_count = module.params.get("set_as_path_count")
    set_additional_community = module.params.get("set_additional_community")
    set_additional_community_criteria = module.params.get("set_additional_community_criteria")





    mso = MSOModule(module)

    template_type = "tenantPolicy"


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}

    template_id = ''
    if templates:
        for temp in templates:
            if temp['templateName'] == template and temp['templateType'] == template_type:
                template_id = temp['templateId']

    if not template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))


    
    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")

    rm_exist = False
    # try to find if the rm policy exist
    if 'template' in mso.existing['tenantPolicyTemplate'] and 'routeMapPolicies' in mso.existing['tenantPolicyTemplate']['template']:
        for count, r in enumerate(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies']):
            if r['name'] == route_map:
                rm_exist = True
                rm_index = count


    if not rm_exist:
        if not template_id:
            mso.fail_json(msg="Route-Map '{route_map}' not found".format(route_map=route_map))


    # try to find if the entry exist in the RM
    entry_exist = False
    if rm_exist and 'rtMapEntryList' in mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]:
        for count, e in enumerate(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList']):
            if e['rtMapContext']['name'] == context_name:
                entry_exist = True
                entry_index = count

    if not entry_exist:
        if not template_id:
            mso.fail_json(msg="Route-Map Entry '{entry}' not found".format(entry=context_name))


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
        if entry_exist:
            del mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index]
            if len(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList']) == 0:
                del mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]
                if len(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies']) == 0:
                    del mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies']
                
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":

        new_rm_entry = {
            "setAction": [{}]
        }
        if set_community:
            if not set_community_criteria:
                mso.fail_json(msg="Community criteria not found")
            new_rm_entry['setAction'][0].update(
                {
                    'setCommunity': {
                        'community': set_community,
                        'criteria': set_community_criteria
                    }
                }
            )
        if set_route_tag:
            new_rm_entry['setAction'][0].update(
                {
                    'setRouteTag': set_route_tag
                }
            )
        if set_dampening:
            new_rm_entry['setAction'][0].update(
                {
                    "setDampening":{
                            "halfLife": half_life,
                            "reuseLimit": re_use_limit,
                            "suppressLimit": supress_limit,
                            "maxSuppressTime": max_suppress_time
                        }
                }
            )
        if set_weight:
            new_rm_entry['setAction'][0].update(
                {
                    "setWeight": set_weight
                }
            )
        if set_next_hop:
            new_rm_entry['setAction'][0].update(
                {
                    "setNextHop": set_next_hop
                }
            )
        if set_preference:
            new_rm_entry['setAction'][0].update(
                {
                    "setPreference": set_preference
                }
            )
        if set_metric:
            new_rm_entry['setAction'][0].update(
                {
                    "setMetric": set_metric
                }
            )
        if set_next_hop_propagate:
            new_rm_entry['setAction'][0].update(
                {
                    "setNextHopPropagate": True
                }
            )
        if set_multipath:
            new_rm_entry['setAction'][0].update(
                {
                    "setNextHopPropagate": True,
                    "setMultiPath": True
                }
            )
        if set_metric_type:
            new_rm_entry['setAction'][0].update(
                {
                    "setMetricType": set_metric_type
                }
            )
        if set_as_path_criteria:
            if set_as_path_criteria == 'prepend':
                if not set_as and set_as_order:
                    mso.fail_json(msg="Set AS Path criteria prepend but set_as or set_as_order not found")
                else:
                    new_rm_entry['setAction'][0].update(
                        {
                            "setAsPath":
                                [
                                    {
                                        "criteria": "prepend",
                                        "pathASNs":
                                            [
                                                {
                                                    "asn": set_as,
                                                    "order": set_as_order
                                                }
                                            ]
                                    }
                                ]
                        }

                    )
            else:
                if not set_as_path_count:
                    mso.fail_json(msg="Set AS Path criteria prepend-last-as but set_as_count not found")
                else:
                    new_rm_entry['setAction'][0].update(
                        {
                            "setAsPath":
                                [
                                    {
                                        "criteria": "prepend-last-as",
                                        "asnCount": 1
                                    }
                                ]
                        }
                    )
        if set_additional_community:
            new_rm_entry['setAction'][0].update(
                {
                    "setAddCommunities":
                        [
                            {
                                "community": set_additional_community,
                                "criteria": "append"
                            }
                        ]
                }
            )

            if len(new_rm_entry['setAction'][0]) == 0:
                mso.fail_json(msg="No set action found")


        #set rules  doesn't exist, need be created
        if 'setAction' not in mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index]:
            mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index].update(new_rm_entry)


            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        else:
            #set rule exist, check if need be updated
            current = mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index].copy()
            diff = diff_dicts(new_rm_entry,current,exclude_key='rtMapContext,matchRule')
            # mso.fail_json(msg=diff)
            if diff:
                mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed



    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
