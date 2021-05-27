#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_clone
short_description: Clone templates
description:
- Clone templates on Cisco ACI Multi-Site.
- Clones only template objects and not site objects.
- This module can only be used on versions of MSO that are 3.3 or greater.
author:
- Anvitha Jain (@anvitha-jain)
options:
  source_schema:
    description:
    - The name of the source_schema.
    type: str
  destination_schema:
    description:
    - The name of the destination_schema.
    type: str
  destination_tenant:
    description:
    - The name of the destination_schema.
    type: str
  source_template_name:
    description:
    - The name of the source template.
    type: str
  destination_template_name:
    description:
    - The name of the destination template.
    type: str
  destination_template_display_name:
    description:
    - The display name of the destination template.
    type: str
  state:
    description:
    - Use C(clone) for adding.
    type: str
    choices: [ clone ]
    default: clone
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_clone
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Clone template in the same schema
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema1
    destination_tenant: ansible_test
    source_template_name: Template1
    destination_template_name: Template1_clone
    destination_template_display_name: Template1_clone
    state: clone
  delegate_to: localhost

- name: Clone template to different schema
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema2
    destination_tenant: ansible_test
    source_template_name: Template2
    destination_template_name: Cloned_template_1
    destination_template_display_name: Cloned_template_1
    state: clone
  delegate_to: localhost

- name: Clone template in the same schema but different tenant attached
  cisco.mso.mso_schema_template_clone:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    source_schema: Schema1
    destination_schema: Schema1
    destination_tenant: common
    source_template_name: Template1_clone
    destination_template_name: Template1_clone_2
    state: clone
  delegate_to: localhost
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        source_schema=dict(type='str'),
        destination_schema=dict(type='str'),
        destination_tenant=dict(type='str'),
        source_template_name=dict(type='str'),
        destination_template_name=dict(type='str'),
        destination_template_display_name=dict(type='str'),
        state=dict(type='str', default='clone', choices=['clone']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'clone', ['destination_schema', 'destination_tenant']],
        ],
    )

    source_schema = module.params.get('source_schema')
    destination_schema = module.params.get('destination_schema')
    destination_tenant = module.params.get('destination_tenant')
    source_template_name = module.params.get('source_template_name')
    destination_template_name = module.params.get('destination_template_name')
    destination_template_display_name = module.params.get('destination_template_display_name')
    state = module.params.get('state')

    mso = MSOModule(module)

    destination_schema_id = None

    # Get source schema id and destination schema id
    schema_summary = mso.query_objs('schemas/list-identity', key='schemas')

    for schema in schema_summary:
        if schema.get('displayName') == source_schema:
            source_schema_id = schema.get('id')
        if schema.get('displayName') == destination_schema:
            destination_schema_id = schema.get('id')
            destination_schema = None
            break
    if destination_schema_id is None:
        mso.fail_json(msg="Schema with the name '{0}' does not exist.".format(destination_schema))

    # Get destination tenant id
    destination_tenant_id = mso.lookup_tenant(destination_tenant)

    path = 'schemas/cloneTemplates'

    if state == 'clone':
        if destination_template_display_name is None:
            destination_template_display_name = destination_template_name

        payload = dict(
            destTenantId=destination_tenant_id,
            destSchemaId=destination_schema_id,
            destSchemaName=destination_schema,
            templatesToBeCloned=[
                dict(
                    schemaId=source_schema_id,
                    templateName=source_template_name,
                    destTemplateName=destination_template_name,
                    destTempDisplayName=destination_template_display_name,
                )
            ],
        )

        mso.sanitize(payload, collate=True)

        mso.previous = {}

        if not mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method='POST', data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
