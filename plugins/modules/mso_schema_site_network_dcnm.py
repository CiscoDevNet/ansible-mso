#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2022, Cassio Lange (@calange) <calange@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_network_dcnm
short_description: Manage site-local Network in schema template
description:
- Manage site-local Network in schema template on Cisco DCNM.
author:
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
  network:
    description:
    - The name of the Network to manage.
    type: str
    aliases: [ name ]
  enable_l3_border_gw:
    description:
    - Enable layer 3 on Border Gateway
    type: Bool 
  dhcp_lo_id:
    description:
    - DHCP loopback id 
    type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a new site Network
  cisco.mso.mso_schema_site_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    network: Network1
    enable_l3_border_gw: True
    dhcp_lo_id: 100
    state: present
  delegate_to: localhost

- name: Remove a site Network
  cisco.mso.mso_schema_site_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    network: Network1
    state: absent
  delegate_to: localhost

- name: Query a specific site Network
  cisco.mso.mso_schema_site_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    network: Network1
    vrf: VRF1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all site Networks
  cisco.mso.mso_schema_site_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
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
        network=dict(type='str', aliases=['name']),
        enable_l3_border_gw=dict(type='bool'),
        dhcp_lo_id=dict(type='int'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['network']],
            ['state', 'present', ['network']],
        ],
    )

    schema = module.params.get('schema')
    site = module.params.get('site')
    template = module.params.get('template').replace(' ', '')
    network = module.params.get('network')
    enable_l3_border_gw = module.params.get('enable_l3_border_gw')
    dhcp_lo_id = module.params.get('dhcp_lo_id')
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
        mso.fail_json(msg="Provided site/template '{0}-{1}' does not exist. Existing sites/templates: {2}".format(site, template, ', '.join(sites)))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = '{0}-{1}'.format(site_id, template)

    # Get Network
    network_ref = '/schemas/{schema_id}/templates/{template}/networks/{network}'.format(schema_id=schema_id, template=template, network=network)
    networks = [v.get('nwRef') for v in schema_obj.get('sites')[site_idx]['networks']]
    if network is not None and network_ref in networks:
        network_idx = networks.index(network_ref)
        network_path = '/sites/{0}/networks/{1}'.format(site_template, network)
        mso.existing = schema_obj.get('sites')[site_idx]['networks'][network_idx]

    if state == 'query':
        if network is None:
            mso.existing = schema_obj.get('sites')[site_idx]['networks']
        elif not mso.existing:
            mso.fail_json(msg="Network '{network}' not found".format(network=network))
        mso.exit_json()

    networks_path = '/sites/{0}/networks'.format(site_template)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=netowork_path))

    elif state == 'present':
        payload = dict(
            nwRef=dict(
                schemaId=schema_id,
                templateName=template,
                nwName=network,
            ),
        )
        if enable_l3_border_gw:
            payload.update(enableL3OnBorder=True)
        elif enable_l3_border_gw is not None:
            if mso.existing and mso.existing.get('enableL3OnBorder') is not None:
                payload.update(enableL3OnBorder=False)

        if enable_l3_border_gw:
            payload.update(enableL3OnBorder=True)
        elif enable_l3_border_gw is not None:
            if mso.existing and mso.existing.get('enableL3OnBorder') is not None:
                payload.update(enableL3OnBorder=False)

        if dhcp_lo_id:
            payload.update(loopbackId=dhcp_lo_id)
        elif dhcp_lo_id is None:
            if mso.existing and mso.existing.get('loopbackId'):
                mso.existing.pop('loopbackId')







        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=network_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=networks_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
