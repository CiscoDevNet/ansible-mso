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
        context_name=dict(type="str", aliases=["name"], required=True),
        template=dict(type="str", required=True),
        route_map=dict(type="str", required=True),
        action=dict(type="str", choices=["permit", "deny"]),
        order=dict(type="int", required=True),
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

    # try to find if the rm policy exist
    rm_exist =False
    if 'template' in mso.existing['tenantPolicyTemplate'] and 'routeMapPolicies' in mso.existing['tenantPolicyTemplate']['template']:
        for count, r in enumerate(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies']):
            if r['name'] == route_map:
                rm_index = count
                rm_exist = True

    if not rm_exist:
        mso.fail_json(msg="Route-Map '{route_map}' not found".format(route_map=route_map))



    # try to find if the entry exist in the RM
    entry_exist = False
    if 'rtMapEntryList' in mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]:
        for count, e in enumerate(mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList']):
            if e['rtMapContext']['name'] == context_name:
                entry_exist = True
                entry_index = count



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
                del mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList']
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":

        new_rm_entry = {
            "rtMapContext":
                {
                    "order": order,
                    "name": context_name,
                    "action": action
                },
        }
        
        #rm doesn't exitst, need be created
        if not entry_exist:
            
            if not 'rtMapEntryList' in mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]:
                mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index].update({'rtMapEntryList': []})
            mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'].append(new_rm_entry)

            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed

        else:
            #entry exist, check if need be udpated
            current = mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index].copy()
            diff = diff_dicts(new_rm_entry,current, exclude_key='setAction,matchRule')
            if diff:
                mso.existing['tenantPolicyTemplate']['template']['routeMapPolicies'][rm_index]['rtMapEntryList'][entry_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed



    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
