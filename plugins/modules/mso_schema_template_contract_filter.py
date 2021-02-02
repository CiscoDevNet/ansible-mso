#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_contract_filter
short_description: Manage contract filters in schema templates
description:
- Manage contract filters in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: yes
  template:
    description:
    - The name of the template.
    type: str
    required: yes
  contract:
    description:
    - The name of the contract to manage.
    type: str
    required: yes
  contract_display_name:
    description:
    - The name as displayed on the MSO web interface.
    - This defaults to the contract name when unset on creation.
    type: str
  contract_filter_type:
    description:
    - The type of filters defined in this contract.
    - This defaults to C(both-way) when unset on creation.
    default: both-way
    type: str
    choices: [ both-way, one-way ]
  contract_scope:
    description:
    - The scope of the contract.
    - This defaults to C(vrf) when unset on creation.
    type: str
    choices: [ application-profile, global, tenant, vrf ]
  filter:
    description:
    - The filter to associate with this contract.
    type: str
    aliases: [ name ]
  filter_template:
    description:
    - The template name in which the filter is located.
    type: str
  filter_schema:
    description:
    - The schema name in which the filter is located.
    type: str
  filter_type:
    description:
    - The type of filter to manage.
    type: str
    choices: [ both-way, consumer-to-provider, provider-to-consumer ]
    default: both-way
    aliases: [ type ]
  filter_directives:
    description:
    - A list of filter directives.
    type: list
    elements: str
    choices: [ log, none, policy_compression ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_filter_entry
notes:
- Due to restrictions of the MSO REST API this module creates contracts when needed, and removes them when the last filter has been removed.
- Due to restrictions of the MSO REST API concurrent modifications to contract filters can be dangerous and corrupt data.
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a new contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    contract_scope: global
    filter: Filter 1
    state: present
  delegate_to: localhost

- name: Remove a contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    filter: Filter 1
    state: absent
  delegate_to: localhost

- name: Query a specific contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    filter: Filter 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contract filters
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec

FILTER_KEYS = {
    'both-way': 'filterRelationships',
    'consumer-to-provider': 'filterRelationshipsConsumerToProvider',
    'provider-to-consumer': 'filterRelationshipsProviderToConsumer',
}


def main():

    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        contract=dict(type='str', required=True),
        contract_display_name=dict(type='str'),
        contract_scope=dict(type='str', choices=['application-profile', 'global', 'tenant', 'vrf']),
        contract_filter_type=dict(type='str', default='both-way', choices=['both-way', 'one-way']),
        filter=dict(type='str', aliases=['name']),  # This parameter is not required for querying all objects
        filter_directives=dict(type='list', elements='str', choices=['log', 'none', 'policy_compression']),
        filter_template=dict(type='str'),
        filter_schema=dict(type='str'),
        filter_type=dict(type='str', default='both-way', choices=list(FILTER_KEYS), aliases=['type']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['filter']],
            ['state', 'present', ['filter']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    contract = module.params.get('contract')
    contract_display_name = module.params.get('contract_display_name')
    contract_filter_type = module.params.get('contract_filter_type')
    contract_scope = module.params.get('contract_scope')
    filter_name = module.params.get('filter')
    filter_directives = module.params.get('filter_directives')
    filter_template = module.params.get('filter_template')
    if filter_template is not None:
        filter_template = filter_template.replace(' ', '')
    filter_schema = module.params.get('filter_schema')
    filter_type = module.params.get('filter_type')
    state = module.params.get('state')

    mso = MSOModule(module)

    contract_ftype = 'bothWay' if contract_filter_type == 'both-way' else 'oneWay'

    if contract_filter_type == 'both-way' and filter_type != 'both-way':
        mso.fail_json(msg="You are adding 'one-way' filters to a 'both-way' contract")
    elif contract_filter_type != 'both-way' and filter_type == 'both-way':
        mso.fail_json(msg="You are adding 'both-way' filters to a 'one-way' contract")
    if filter_template is None:
        filter_template = template

    if filter_schema is None:
        filter_schema = schema

    filter_key = FILTER_KEYS.get(filter_type)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))
    template_idx = templates.index(template)

    filter_schema_id = mso.lookup_schema(filter_schema)
    # Get contracts

    mso.existing = {}
    contract_idx = None
    filter_idx = None
    contracts = [c.get('name') for c in schema_obj.get('templates')[template_idx]['contracts']]

    if contract in contracts:
        contract_idx = contracts.index(contract)
        contract_obj = schema_obj.get('templates')[template_idx]['contracts'][contract_idx]

        filters = [f.get('filterRef') for f in schema_obj.get('templates')[template_idx]['contracts'][contract_idx][filter_key]]
        filter_ref = mso.filter_ref(schema_id=filter_schema_id, template=filter_template, filter=filter_name)
        if filter_ref in filters:
            filter_idx = filters.index(filter_ref)
            filter_path = '/templates/{0}/contracts/{1}/{2}/{3}'.format(template, contract, filter_key, filter_name)
            filter = contract_obj.get(filter_key)[filter_idx]
            mso.existing = mso.update_filter_obj(contract_obj, filter, filter_type)

    if state == 'query':
        if contract_idx is None:
            mso.fail_json(msg="Provided contract '{0}' does not exist. Existing contracts: {1}".format(contract, ', '.join(contracts)))

        if filter_name is None:
            mso.existing = contract_obj.get(filter_key)
            for filter in mso.existing:
                filter = mso.update_filter_obj(contract_obj, filter, filter_type)

        elif not mso.existing:
            mso.fail_json(msg="FilterRef '{filter_ref}' not found".format(filter_ref=filter_ref))
        mso.exit_json()

    ops = []
    contract_path = '/templates/{0}/contracts/{1}'.format(template, contract)
    filters_path = '/templates/{0}/contracts/{1}/{2}'.format(template, contract, filter_key)
    mso.previous = mso.existing

    if state == 'absent':
        mso.proposed = mso.sent = {}

        if contract_idx is None:
            # There was no contract to begin with
            pass
        elif filter_idx is None:
            # There was no filter to begin with
            pass
        elif len(filters) == 1:
            # There is only one filter, remove contract
            mso.existing = {}
            ops.append(dict(op='remove', path=contract_path))
        else:
            # Remove filter
            mso.existing = {}
            ops.append(dict(op='remove', path=filter_path))

    elif state == 'present':
        if filter_directives is None:
            filter_directives = ['none']

        if 'policy_compression' in filter_directives:
            filter_directives.remove('policy_compression')
            filter_directives.append('no_stats')

        payload = dict(
            filterRef=dict(
                filterName=filter_name,
                templateName=filter_template,
                schemaId=filter_schema_id,
            ),
            directives=filter_directives,
        )

        mso.sanitize(payload, collate=True, unwanted=['filterType', 'contractScope', 'contractFilterType'])
        mso.existing = mso.sent
        if contract_scope is None or contract_scope == 'vrf':
            contract_scope = 'context'
        if contract_idx is None:
            # Contract does not exist, so we have to create it
            if contract_display_name is None:
                contract_display_name = contract
            payload = {
                'name': contract,
                'displayName': contract_display_name,
                'filterType': contract_ftype,
                'scope': contract_scope,
            }
            ops.append(dict(op='add', path='/templates/{0}/contracts/-'.format(template), value=payload))

        else:
            # Contract exists, but may require an update
            if contract_display_name is not None:
                ops.append(dict(op='replace', path=contract_path + '/displayName', value=contract_display_name))
            ops.append(dict(op='replace', path=contract_path + '/filterType', value=contract_ftype))
            ops.append(dict(op='replace', path=contract_path + '/scope', value=contract_scope))

        if contract_display_name:
            mso.existing['displayName'] = contract_display_name
        else:
            mso.existing['displayName'] = contract_obj.get('displayName')
        mso.existing['filterType'] = filter_type
        mso.existing['contractScope'] = contract_scope
        mso.existing['contractFilterType'] = contract_ftype

        if filter_idx is None:
            # Filter does not exist, so we have to add it
            ops.append(dict(op='add', path=filters_path + '/-', value=mso.sent))

        else:
            # Filter exists, we have to update it
            ops.append(dict(op='replace', path=filter_path, value=mso.sent))

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
