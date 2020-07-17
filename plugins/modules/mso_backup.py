#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_backup
short_description: Manage backups
description:
- Manage backups on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
version_added: '2.8'
options:
  location_type:
    description:
    - The location of the backup to be stored
    type: str
  backup:
    description:
    - The name given to the backup
    type: str
    aliases: [ name ]
  description:
    description:
    - Brief information about backup
    type: str
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
- name: Create a new backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: local
    state: present
  delegate_to: localhost
- name: Remove a Backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: absent
  delegate_to: localhost
- name: Query a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: query
  delegate_to: localhost
  register: query_result
- name: Query all backups
  cisco.mso.mso_backup:
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, issubset


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        location_type=dict(type='str'),
        description=dict(type='str'),
        backup=dict(type='str', aliases=['name']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    description = module.params.get('description')
    location_type = module.params.get('location_type')
    state = module.params.get('state')
    backup = module.params.get('backup')

    mso = MSOModule(module)

    backup_id = None
    path = 'backups'
    count_backups = 0
    mso.existing = mso.query_objs('backups')
    if backup:
        if mso.existing:
            data = mso.existing
            mso.existing = []
            for index_of_name in range(0, len(data)):
                backup_id = data[index_of_name]['id']
                if (str(backup) + '_' + backup_id == data[index_of_name]['metadata']['name']):
                    path = 'backups/{id}'.format(id=backup_id)
                    count_backups += 1
                    mso.existing.append(data[index_of_name])
            if count_backups < 1:
                mso.existing = mso.get_obj(path, name=backup)

    if state == 'query':
        pass
        mso.exit_json()

    if state == 'absent':
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method='DELETE')
        mso.exit_json()

    path = 'backups'
    mso.existing = mso.get_obj(path, name=backup)

    if state == 'present':
        mso.previous = mso.existing

        payload = dict(
            name=backup,
            description=description,
            loationType=location_type
        )

        mso.sanitize(payload, collate=True)

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request(path, method='POST', data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
