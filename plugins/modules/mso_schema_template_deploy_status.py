#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_deploy_status
short_description: Check status of objects before deployment to site
description:
- Check status of objects in a template of a schema
author:
- Shreyas Srish (@shrsr)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    aliases: [ name ]
  template:
    description:
    - The name of the template.
    type: str
  state:
    description:
    - Use C(status) for listing status of objects.
    type: str
    choices: [ status ]
    default: status
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''

- name: Query status of objects in a template before deployment
  cisco.mso.mso_schema_template_deploy_status:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template1
    state: status
  delegate_to: localhost
  register: query_result

- name: Query status of objects in all templates before deployment
  cisco.mso.mso_schema_template_deploy_status:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    state: status
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', aliases=['name']),
        template=dict(type='str'),
        state=dict(type='str', default='status', choices=['status']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'status', ['schema']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template')
    if template is not None:
        template = template.replace(' ', '')
    state = module.params.get('state')

    mso = MSOModule(module)

    schema_id = None
    path = 'schemas'

    get_schema = mso.get_obj(path, displayName=schema)
    if get_schema:
        schema_id = get_schema.get('id')
        path = 'schemas/{id}/policy-states'.format(id=schema_id)
    else:
        mso.fail_json(msg="Schema '{0}' not found.".format(schema))

    if state == 'status':
        mso.existing = mso.request(path, method='GET')
        if template:
            for objects in mso.existing.get('policyStates'):
                if objects.get('templateName') == template:
                    mso.existing = objects
                    break
                else:
                    mso.existing = {}
            if not mso.existing:
                mso.fail_json(msg="Template '{0}' not found.".format(template))

    mso.exit_json()


if __name__ == "__main__":
    main()
