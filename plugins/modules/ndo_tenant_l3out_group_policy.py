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
        group_policy=dict(type="str", aliases=["name"], required=True),
        l3out=dict(type="str", required=True),
        template=dict(type="str", required=True),
        description=dict(type="str", aliases=["descr"]),
        group_policy_type=dict(type="str", choices=["interface"], default="interface"),
        interface_routing_policy=dict(type="str"),
        interface_routing_policy_template=dict(type="str"),
        bfd=dict(type="bool", default=False),
        bfd_multi_hop=dict(type="bool", default=False),
        qos_class=dict(type="str", choices=["unspecified", "level1", "level2","level3","level4","level5","level6"], default="unspecified"),
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
    description = module.params.get("description")
    l3out = module.params.get("l3out")
    group_policy = module.params.get("group_policy")
    group_policy_type = module.params.get("group_policy_type")
    interface_routing_policy = module.params.get("interface_routing_policy")
    interface_routing_policy_template = module.params.get("interface_routing_policy_template")
    bfd = module.params.get("bfd")
    bfd_multi_hop = module.params.get("bfd_multi_hop")
    qos_class =module.params.get("qos_class")





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

    if not l3out_exist:
        mso.fail_json(msg="L3out '{l3out}' not found".format(l3out=l3out))


    # try to find if the interface Groups exist
    group_policy_exist = False
    try:
        for count, e in enumerate(mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups']):
            if e['name'] == group_policy:
                group_policy_exist = True
                group_policy_index = count
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
        if group_policy_exist:
            del mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups'][group_policy_index]
            if len(mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups']) == 0:
                del mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups']

            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":
        if group_policy_type == "interface" and  interface_routing_policy and interface_routing_policy_template:
            interface_policy_template_id = get_template_id(template_name=interface_routing_policy_template, template_type="tenantPolicy", template_dict=templates)
        else:
            mso.fail_json(msg="Interface routing policy is required")

        if interface_policy_template_id:
            int_policy_template_dict = mso.request(path=f"templates/{interface_policy_template_id}", method="GET", api_version="v1")
        else:
            mso.fail_json(msg="Template '{template}' not found".format(template=interface_routing_policy_template))

        l3out_int_pol_uuid = ''
        try:
            for count, e in enumerate(int_policy_template_dict['tenantPolicyTemplate']['template']['l3OutIntfPolGroups']):
                if e['name'] == interface_routing_policy:
                    l3out_int_pol_uuid =  e['uuid']
        except:
            pass
        
        if not l3out_int_pol_uuid:
            mso.fail_json(msg="Interface Policy group '{interface}' not found".format(interface=interface_routing_policy))

        new_interface_group = {
            "name" : group_policy,
            "interfaceRoutingPolicyRef": l3out_int_pol_uuid,
            "qosPriority": qos_class
        }
        if description:
            new_interface_group['description'] = description

        if bfd:
            new_interface_group['bfd'] = {"authEnabled": False}

        if bfd_multi_hop:
            new_interface_group['bfdMultiHop'] = {"authEnabled": False}

        if not group_policy_exist:
            if 'interfaceGroups' not in mso.existing['l3outTemplate']['l3outs'][l3out_index]:
                mso.existing['l3outTemplate']['l3outs'][l3out_index].update({'interfaceGroups' : []})

            mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups'].append(new_interface_group)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        else:
            # check if need be updated
            current = mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups'][group_policy_index].copy()
            diff = diff_dicts(new_interface_group,current)
            if diff:
                mso.existing['l3outTemplate']['l3outs'][l3out_index]['interfaceGroups'][group_policy_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed





    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
