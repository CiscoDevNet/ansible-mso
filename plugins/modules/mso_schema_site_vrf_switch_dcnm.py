#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2022, Cassio Lange (@calange) <calange@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_vrf_switch_dcnm
short_description: Manage Switch association with  site-local VRFs in schema template
description:
- Manage Switch association with  site-local VRFs in schema template on Cisco DCNN.
author:
- Anvitha Jain (@anvitha-jain)
- Dag Wieers (@dagwieers)
- Cassio Lange (@calange)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: yes
  site:
    description:
    - The name of the site.
    type: str
    required: yes
  template:
    description:
    - The name of the template.
    type: str
    required: yes
  vrf:
    description:
    - The name of the VRF.
    type: str
    required: yes
  switch_serial_number:
    description:
    - Switch Serial Number
    type: str 
    required: yes
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
'''

EXAMPLES = r'''
- name: Add Switch to site VRF
  cisco.mso.mso_schema_site_network_switch_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    switch_serial_number: ABCD123
    state: present
  delegate_to: localhost

- name: Remove Switch from site VRF
  cisco.mso.mso_schema_site_network_switch_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    switch_serial_number: ABCD123
    state: absent
  delegate_to: localhost

- name: Query a specific site VRF
  cisco.mso.mso_schema_site_network_switch_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
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
        schema=dict(type='str', required=True),
        site=dict(type='str', required=True),
        template=dict(type='str', required=True),
        vrf=dict(type='str', required=True),
        switch_serial_number=dict(type='str', required=True),  # This parameter is not required for querying all objects
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['vrf']],
            ['state', 'present', ['vrf']],
        ],
    )

    schema = module.params.get('schema')
    site = module.params.get('site')
    template = module.params.get('template').replace(' ', '')
    vrf = module.params.get('vrf')
    switch_serial_number = module.params.get('switch_serial_number')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if 'sites' not in schema_obj:
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get('siteId'), s.get('templateName')) for s in schema_obj.get('sites')]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = '{0}-{1}'.format(site_id, template)

    # Get VRF
    vrf_ref = mso.vrf_ref(schema_id=schema_id, template=template, vrf=vrf)
    vrfs = [v.get('vrfRef') for v in schema_obj.get('sites')[site_idx]['vrfs']]
    vrfs_name = [mso.dict_from_ref(v).get('vrfName') for v in vrfs]
    if vrf_ref not in vrfs:
        mso.fail_json(msg="Provided vrf '{0}' does not exist. Existing vrfs: {1}".format(vrf, ', '.join(vrfs_name)))
    vrf_idx = vrfs.index(vrf_ref)

    # Get DCNM Static Leafs
    leafs = [r.get('switchSN') for r in schema_obj.get('sites')[site_idx]['vrfs'][vrf_idx]['dcnmStaticLeafs']]
    if switch_serial_number is not None and switch_serial_number in leafs:
        leaf_idx = leafs.index(switch_serial_number)
        leaf_path = '/sites/{0}/vrfs/{1}/dcnmStaticLeafs/{2}'.format(site_template, vrf, leaf_idx)
        mso.existing = schema_obj.get('sites')[site_idx]['vrfs'][vrf_idx]['dcnmStaticLeafs'][leaf_idx]

    if state == 'query':
        if switch_serial_number is None:
            mso.existing = schema_obj.get('sites')[site_idx]['vrfs'][vrf_idx]['dcnmStaticLeafs']
        elif not mso.existing:
            mso.fail_json(msg="Switch '{serial}' not found".format(serial=switch_serial_number))
        mso.exit_json()

    leafs_path = '/sites/{0}/vrfs/{1}/dcnmStaticLeafs'.format(site_template, vrf)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=leaf_path))

    elif state == 'present':

        payload = dict(
            switchSN=switch_serial_number
        )


        mso.sanitize(payload, collate=True)
        if mso.existing:
            #ops.append(dict(op='replace', path=leaf_path, value=mso.sent))
            mso.exit_json()
        else:
            ops.append(dict(op='add', path=leafs_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
