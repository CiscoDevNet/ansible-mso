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
        domain=dict(type="str", required=True),
        template=dict(type="str", required=True),
        interface=dict(type="str", required=True),
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
    interface = module.params.get("interface")
    domain = module.params.get("domain")



    mso = MSOModule(module)

    template_type = "fabricPolicy"


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}

    if templates:
        for temp in templates:
            if temp['templateName'] == template and temp['templateType'] == template_type:
                template_id = temp['templateId']

    if not template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))


    ##get the template

    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")

    domain_uuid = ''

    domain_list = ['domains', 'l3Domains']

    # try to find if the domain exist
    for entry in domain_list:
        if 'template' in mso.existing['fabricPolicyTemplate'] and entry in mso.existing['fabricPolicyTemplate']['template']:
            for count, d in enumerate(mso.existing['fabricPolicyTemplate']['template'][entry]):
                if d['name'] == domain:
                    domain_type = entry
                    domain_uuid = d['uuid']

    if not domain_uuid:
        mso.fail_json(msg="Domain '{domain}' not found".format(domain=domain))

    interface_exist = False
    if 'template' in mso.existing['fabricPolicyTemplate'] and 'interfacePolicyGroups' in mso.existing['fabricPolicyTemplate']['template']:
        for count, ipg in enumerate(mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups']):
            if ipg['name'] == interface:
                interface_index = count
                interface_exist = True

    if not interface_exist:
        mso.fail_json(msg="Interface '{interface}' not found".format(interface=interface))


    domain_associated = False
    if 'domains' in mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]:
        for count, d in enumerate(mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]['domains']):
                if d == domain_uuid:
                    domain_associated = True
                    domain_index = count

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
        if domain_associated:
            del mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]['domains'][domain_index]
            if len(mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]['domains']) == 0:
                del mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]['domains']
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":

        #domain doesn't exitst, need be created
        if not domain_associated:
            if not 'domains' in mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]:
                mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index].update({'domains': []})
            mso.existing['fabricPolicyTemplate']['template']['interfacePolicyGroups'][interface_index]['domains'].append(domain_uuid)

            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed

    
    
    

    mso.exit_json()


if __name__ == "__main__":
    main()
