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
        interface=dict(type="str", aliases=["name"], required=True),
        description=dict(type="str", aliases=["descr"]),
        template=dict(type="str", required=True),
        interface_type=dict(type="str", choices=["physical", "breakout", "port-channel", "vpc", "fex"], required=True),
        node1=dict(type="str", required=True),
        node2=dict(type="str"),
        interfaces_node1=dict(type="str", required=True),
        interfaces_node2=dict(type="str"),
        interface_policy=dict(type="str"),
        fabric_policy_template=dict(type="str"),
        breakout_interface=dict(type="str", choices=["4x10G", "4x25G", "4x100G"]),
        fex_id=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
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
    interface = module.params.get("interface")
    interface_type = module.params.get("interface_type")
    node1 = module.params.get("node1")
    node2 = module.params.get("node2")
    interfaces_node1 = module.params.get("interfaces_node1")
    interfaces_node2 = module.params.get("interfaces_node2")
    interface_policy = module.params.get("interface_policy")
    breakout_interface = module.params.get("breakout_interface")
    fabric_policy_template = module.params.get("fabric_policy_template")
    fex_id = module.params.get("fex_id")



    mso = MSOModule(module)

    template_type = "fabricResource"
    physical_types = ["physical", "breakout"]
    requires_policy = ["physical", "port-channel", "vpc"]
    interface_type_path = {
        "physical": "interfaceProfiles",
        "breakout": "interfaceProfiles",
        "port-channel": "portChannels",
        "vpc": "virtualPortChannels",
        "fex": "fexDevices"
    }


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}
    
    template_id = ''
    template_policy_id = ''

    #try to find the fabric resources template
    if templates:
        for temp in templates:
            if temp['templateName'] == template and temp['templateType'] == template_type:
                template_id = temp['templateId']

    if not template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))

    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")
    
    interface_exist = False
    #try to find if interface exist
    # if 'template' in mso.existing['fabricResourceTemplate'] and interface_type_path[interface_type] in mso.existing['fabricResourceTemplate']['template']:
    if interface_type_path[interface_type] in mso.existing['fabricResourceTemplate']['template'] and mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]]:
        for count, d in enumerate(mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]]):
            if d['name'] == interface:
                interface_exist = True
                interface_index = count

    interface_policy_uuid = ''
    if interface_type in requires_policy:
        # try to find the find fabric policies template
        for temp in templates:
            if temp['templateName'] == fabric_policy_template and temp['templateType'] == 'fabricPolicy':
                template_policy_id = temp['templateId']

        if not template_policy_id:
            mso.fail_json(msg="Template '{template}' not found".format(template=fabric_policy_template))

        fabric_pol_temp =  mso.request(path=f"templates/{template_policy_id}", method="GET", api_version="v1")

        # try to find if the interface policy exist
        if 'template' in fabric_pol_temp['fabricPolicyTemplate'] and 'interfacePolicyGroups' in fabric_pol_temp['fabricPolicyTemplate']['template']:

            for count, i in enumerate(fabric_pol_temp['fabricPolicyTemplate']['template']['interfacePolicyGroups']):
                if i['name'] == interface_policy:
                    interface_policy_uuid = i['uuid']

        if not interface_policy_uuid:
            mso.fail_json(msg="Interface Policy '{policy}' not found".format(policy=interface_policy))

    if interface_type == 'vpc' and (not node2 or not interfaces_node2):
        mso.fail_json(msg="Interface type VPC requires second node and interfaces")

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
            del mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]][interface_index]
            if len(mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]]) == 0:
                mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]] = None
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        new_interface = {
            "name": interface,
            "description": "",
            "adminState": "up"
        }
        if description:
            new_interface['description'] = description
        if interface_type == 'physical':
            new_interface.update(
                {
                    "nodes": [
                        node1
                    ],
                    "interfaces": interfaces_node1,
                    "policyGroupType": "physical",
                    "policy": interface_policy_uuid,
                    "interfaceDescriptions": None
                }
            )
        elif interface_type == 'breakout':
            new_interface.update(
                {
                    "nodes": [
                        node1
                    ],
                    "interfaces": interfaces_node1,
                    "policyGroupType": "breakout",
                    "breakoutMode": breakout_interface,
                }
            )
        elif interface_type == 'port-channel':
            new_interface.update(
                {
                    "templateId": template_id,
                    "node": node1,
                    "memberInterfaces": interfaces_node1,
                    "policy": interface_policy_uuid,
                    "interfaceDescriptions": None
                }
            )
        elif interface_type == 'vpc':
            new_interface.update(
                {
                    "templateId": template_id,
                    "node1Details":
                        {
                            "node": node1,
                            "memberInterfaces": interfaces_node1,
                            "role": "standby"
                        },
                    "node2Details":
                        {
                            "node": node2,
                            "memberInterfaces": interfaces_node2,
                            "role": "standby"
                        },
                    "policy": interface_policy_uuid,
                    "interfaceDescriptions": None
                }
            )
        else:
            new_interface.update(
                {
                    "nodes":
                        [
                            node1
                        ],
                    "interfaces": interfaces_node1,
                    "fexId": fex_id
                }
            )
            new_interface.pop('adminState')
        
        #interface doesn't exitst, need be created
        if not interface_exist:
            if not interface_type_path[interface_type] in mso.existing['fabricResourceTemplate']['template']:
                mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]] = []
            if not mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]]:
                mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]] = []
            mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]].append(new_interface)
            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        else:
            #interface exist check if need be updated
            current = mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]][interface_index].copy()
            diff = diff_dicts(new_interface, current)
            if diff:
                mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]][interface_index] = update_payload(diff=diff, payload=mso.existing['fabricResourceTemplate']['template'][interface_type_path[interface_type]][interface_index])
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed

    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
