#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from copy import deepcopy

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_tenant
short_description: Manage tenants
description:
- Manage tenants on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name of the tenant to be displayed in the web UI.
    type: str
  description:
    description:
    - The description for this tenant.
    type: str
  users:
    description:
    - A list of associated users for this tenant.
    - Using this property will replace any existing associated users.
    - Admin user is always added to the associated user list irrespective of this parameter being used.
    type: list
    elements: str
  sites:
    description:
    - A list of associated sites for this tenant.
    - Using this property will replace any existing associated sites.
    type: list
    elements: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a new tenant
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    display_name: North European Datacenter
    description: This tenant manages the NEDC environment.
    state: present
  delegate_to: localhost

- name: Remove a tenant
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    state: absent
  delegate_to: localhost

- name: Query a tenant
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all tenants
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
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
        description=dict(type='str'),
        display_name=dict(type='str'),
        tenant=dict(type='str', aliases=['name']),
        users=dict(type='list', elements='str'),
        sites=dict(type='list', elements='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant']],
            ['state', 'present', ['tenant']],
        ],
    )

    description = module.params.get('description')
    display_name = module.params.get('display_name')
    tenant = module.params.get('tenant')
    state = module.params.get('state')

    mso = MSOModule(module)
    # Convert sites and users
    sites = mso.lookup_sites(module.params.get('sites'))
    # users = mso.lookup_users(module.params.get('users'))
    get_users = module.params.get('users')
    if not get_users:
        get_users = []
        get_users.append(module.params.get('username'))

    new_users = mso.lookup_users(get_users)

    tenant_id = None
    path = 'tenants'

    # Query for existing object(s)
    if tenant:
        mso.existing = mso.get_obj(path, name=tenant)
        if mso.existing:
            tenant_id = mso.existing.get('id')
            # If we found an existing object, continue with it
            path = 'tenants/{id}'.format(id=tenant_id)
    else:
        mso.existing = mso.query_objs(path)

    if state == 'query':
        pass

    elif state == 'absent':
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method='DELETE')

    elif state == 'present':
        mso.previous = mso.existing

        if mso.existing:
            users = deepcopy(mso.existing['userAssociations'])
            for new_user in new_users:
                if new_user not in users:
                    users.append(new_user)
        else:
            users = new_users

        payload = dict(
            description=description,
            id=tenant_id,
            name=tenant,
            displayName=display_name,
            siteAssociations=sites,
            userAssociations=users,
        )

        mso.sanitize(payload, collate=True)
        # Ensure displayName is not undefined
        if mso.sent.get('displayName') is None:
            mso.sent['displayName'] = tenant

        if mso.existing:
            if mso.check_changed():
                if module.check_mode:
                    mso.existing = mso.proposed
                else:
                    mso.existing = mso.request(path, method='PUT', data=mso.sent)
        else:
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method='POST', data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
