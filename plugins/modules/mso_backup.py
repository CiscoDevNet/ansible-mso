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
  remote_location:
    description:
    - The remote location's name where the backup should be stored
    type: str
  remote_path:
   description:
    - This path is relative to the remote location.
    - A '/' is automatically added between the remote location folder and this path.
    - This folder structure should already exist on the remote location.
   type: str
  description:
    description:
    - Brief information about the backup.
    type: str
  destination:
    description:
    - Location where to download the backup to
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(upload) for uploading backup.
    - Use C(restore) for restoring backup.
    - Use C(download) for downloading backup.
    - Use C(move) for moving backup from local to remote location.
    type: str
    choices: [ absent, present, query, upload, restore, download, move ]
    default: present
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Create a new local backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: local
    state: present
  delegate_to: localhost

- name: Create a new remote backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: remote
    remote_location: ansible_test
    state: present
  delegate_to: localhost

- name: Move backup to remote location
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup0
    remote_location: ansible_test
    remote_path: test
    state: move
  delegate_to: localhost

- name: Download a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    destination: ./
    state: download
  delegate_to: localhost

- name: Upload a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: ./Backup
    state: upload
  delegate_to: localhost

- name: Restore a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: restore
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

- name: Query a backup with its complete name
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup_20200721220043
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
import os


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        location_type=dict(type='str', default='local', choices=['local', 'remote']),
        description=dict(type='str'),
        backup=dict(type='str', aliases=['name']),
        remote_location=dict(type='str'),
        remote_path=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query', 'upload', 'restore', 'download', 'move']),
        destination=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['location_type', 'remote', ['remote_location']],
            ['state', 'absent', ['backup']],
            ['state', 'present', ['backup']],
            ['state', 'upload', ['backup']],
            ['state', 'restore', ['backup']],
            ['state', 'download', ['backup', 'destination']],
            ['state', 'move', ['backup', 'remote_location', 'remote_path']]
        ]
    )

    description = module.params.get('description')
    location_type = module.params.get('location_type')
    state = module.params.get('state')
    backup = module.params.get('backup')
    remote_location = module.params.get('remote_location')
    remote_path = module.params.get('remote_path')
    destination = module.params.get('destination')

    mso = MSOModule(module)

    backup_names = []
    mso.existing = mso.query_objs('backups/backupRecords', key='backupRecords')
    if backup:
        if mso.existing:
            data = mso.existing
            mso.existing = []
            for backup_info in data:
                if backup == backup_info.get('name').split('_')[0] or backup == backup_info.get('name'):
                    mso.existing.append(backup_info)
                    backup_names.append(backup_info.get('name'))

    if state == 'query':
        mso.exit_json()

    elif state == 'absent':
        mso.previous = mso.existing
        if len(mso.existing) > 1:
            mso.module.fail_json(msg="Multiple backups with same name found. Existing backups with similar names: {0}".format(', '.join(backup_names)))
        elif len(mso.existing) == 1:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request('backups/backupRecords/{id}'.format(id=mso.existing[0].get('id')), method='DELETE')
        mso.exit_json()

    elif state == 'present':
        mso.previous = mso.existing

        payload = dict(
            name=backup,
            description=description,
            locationType=location_type
        )

        if location_type == 'remote':
            remote_location_info = mso.lookup_remote_location(remote_location)
            payload.update(remoteLocationId=remote_location_info.get('id'))
            if remote_path:
                remote_path = '{0}/{1}'.format(remote_location_info.get('path'), remote_path)
                payload.update(remotePath=remote_path)

        mso.proposed = payload

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request('backups', method='POST', data=payload)
        mso.exit_json()

    elif state == 'upload':
        mso.previous = mso.existing

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            try:
                payload = dict(name=(os.path.basename(backup), open(backup, 'rb'), 'application/x-gzip'))
                mso.existing = mso.request_upload('backups/upload', fields=payload)
            except Exception:
                mso.module.fail_json(msg="Backup file '{0}' not found!".format(', '.join(backup.split('/')[-1:])))
        mso.exit_json()

    if len(mso.existing) == 0:
        mso.module.fail_json(msg="Backup '{0}' does not exist".format(backup))
    elif len(mso.existing) > 1:
        mso.module.fail_json(msg="Multiple backups with same name found. Existing backups with similar names: {0}".format(', '.join(backup_names)))

    elif state == 'restore':
        mso.previous = mso.existing
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request('backups/{id}/restore'.format(id=mso.existing[0].get('id')), method='PUT')

    elif state == 'download':
        mso.previous = mso.existing
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request_download('backups/{id}/download'.format(id=mso.existing[0].get('id')), destination=destination)

    elif state == 'move':
        mso.previous = mso.existing
        remote_location_info = mso.lookup_remote_location(remote_location)
        remote_path = '{0}/{1}'.format(remote_location_info.get('path'), remote_path)
        payload = dict(
            remoteLocationId=remote_location_info.get('id'),
            remotePath=remote_path,
            backupRecordId=mso.existing[0].get('id')
        )
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request('backups/remote-location', method='POST', data=payload)

    mso.exit_json()


if __name__ == "__main__":
    main()
