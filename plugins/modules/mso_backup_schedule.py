#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: mso_backup_schedule
short_description: Manages backup schedules
description:
- Manage backup schedules on Cisco ACI Multi-Site.
author:
- Akini Ross (@akinross)
options:
  start_date:
    description:
    - The date to start the scheduler in format YYYY-MM-DD
    - If no date is provided, the current date will be used.
    type: str
  start_time:
    description:
    - The time to start the scheduler in format HH:MM:SS
    - If no time is provided, midnight "00:00:00" will be used.
    type: str
  frequency_unit:
    description:
    - The interval unit type
    choices: [ hours, days ]
    type: str
  frequency_length:
    description:
    - Amount of hours or days for the schedule trigger frequency
    type: int
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
- name: Get current backup schedule
  cisco.mso.mso_backup_schedule:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Set backup schedule
  cisco.mso.mso_backup_schedule:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    frequency_unit: hours
    frequency_length: 7
    remote_location: ansible_test
    state: present
  delegate_to: localhost

- name: Set backup schedule with date and time
  cisco.mso.mso_backup_schedule:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    frequency_unit: days
    frequency_length: 1
    remote_location: ansible_test
    remote_path: test
    start_time: 20:57:36
    start_date: 2023-04-09
    state: present
  delegate_to: localhost

- name: Delete backup schedule
  cisco.mso.mso_backup_schedule:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: absent
  delegate_to: localhost
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from datetime import date, datetime, time, tzinfo, timedelta

# UTC Timezone implementation as datetime.timezone is not supported in Python 2.7


class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        start_date=dict(type='str'),
        start_time=dict(type='str'),
        frequency_unit=dict(type='str', choices=['hours', 'days']),
        frequency_length=dict(type='int'),
        remote_location=dict(type='str'),
        remote_path=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['frequency_unit', 'frequency_length', 'remote_location']]
        ]
    )

    start_date = module.params.get('start_date')
    start_time = module.params.get('start_time')
    frequency_unit = module.params.get('frequency_unit')
    frequency_length = module.params.get('frequency_length')
    remote_location = module.params.get('remote_location')
    remote_path = module.params.get('remote_path')
    state = module.params.get('state')

    mso = MSOModule(module)
    api_path = 'backups/schedule'
    mso.existing = mso.request(api_path, method='GET')

    if state == 'absent':
        mso.previous = mso.existing
        if module.check_mode:
            mso.existing = {}
        else:
            mso.existing = mso.request(api_path, method='DELETE')

    elif state == 'present':
        mso.previous = mso.existing

        remote_location_info = mso.lookup_remote_location(remote_location)

        # If no time has been provided default to midnight "00:00:00".
        try:
            start_time = time.fromisoformat(start_time) if start_time else time()
        except Exception as e:
            module.fail_json(msg="Failed to parse time format 'HH:MM:SS' %s, %s" % (start_time, e))

        # If no date has been provided default to current date.
        try:
            start_date = date.fromisoformat(start_date) if start_date else datetime.now(UTC()).date()
        except Exception as e:
            module.fail_json(msg="Failed to parse date format 'YYYY-MM-DD' %s, %s" % (start_date, e))

        payload = dict(
            startDate="{0}Z".format(datetime.combine(start_date, start_time).isoformat(timespec='milliseconds')),
            intervalTimeUnit=frequency_unit.upper(),
            intervalLength=frequency_length,
            remoteLocationId=remote_location_info.get('id'),
            locationType="remote"
        )

        if remote_path:
            payload.update(remotePath='{0}/{1}'.format(remote_location_info.get('path'), remote_path))

        mso.proposed = payload

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request(api_path, method='POST', data=payload)

    mso.exit_json()


if __name__ == "__main__":
    main()
