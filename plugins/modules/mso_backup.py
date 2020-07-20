#!/usr/bin/python
# -*- coding: utf-8 -*-

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
short_description: Manages backups
description:
- Manage backups on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
options:
  location_type:
    description:
    - The type of location for the backup to be stored
    type: str
    choices: [ local, remote]
    default: local
  backup:
    description:
    - The name given to the backup
    type: str
    aliases: [ name ]
  remote_location_name:
    description:
    - The remote location's name for the backup to be stored
    type: str
  backup_remote_path:
   description:
    - The sub directory for the backup to be stored
   type: str
  description:
    description:
    - Brief information about the backup
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
- name: Create a new backup in a local location
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: local
    state: present
  delegate_to: localhost

- name: Create a new backup in a remote location
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: remote
    remote_location_name: ansible_test
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        location_type=dict(type='str', default='local', choices=['local', 'remote']),
        description=dict(type='str'),
        backup=dict(type='str', aliases=['name']),
        remote_location_name=dict(type='str'),
        backup_remote_path=dict(type='str'),
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
    remote_location_name = module.params.get('remote_location_name')
    backup_remote_path = module.params.get('backup_remote_path')

    mso = MSOModule(module)

    if remote_location_name:
        remote_location_id = (mso.lookup_remote_location(remote_location_name))[0]
        remote_path = (mso.lookup_remote_location(remote_location_name))[1]

    if backup_remote_path:
        remote_path += '/' + backup_remote_path

    backup_id = None
    path = 'backups'
    mso.existing = mso.query_objs('backups/backupRecords', key='backupRecords')
    if backup:
        if mso.existing:
            data = mso.existing
            mso.existing = []
            for backup_info in data:
                backup_id = backup_info.get('id')
                if backup == backup_info.get('name').split('_')[0]:
                    path = 'backups/backupRecords/{id}'.format(id=backup_id)
                    mso.existing.append(backup_info)
            if len(mso.existing) < 1:
                mso.existing = mso.get_obj(path, name=backup)

    if state == 'query':
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
            locationType=location_type
        )
        if location_type == 'remote':
            payload.update(remoteLocationId=remote_location_id, remotePath=remote_path)

        mso.sanitize(payload, collate=True)

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request(path, method='POST', data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
