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
module: mso_schema_site_network_dhcp_dcnm
short_description: Manage DHCP relay on site-local Network in schema template
description:
-Manage DHCP relay on site-local Network in schema template on Cisco DCNM
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
  network:
    description:
    - The name of the network.
    type: str
    required: yes
  dhcp_vrf:
    description:
    - The name of the VRF.
    type: str
    required: yes
  dhcp_address:
    description:
    - IP address of the DHCP server .
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
- name: Add DHCP Server at site Network
  cisco.mso.mso_schema_site_network_dhcp_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    network: Network1
    dhcp_vrf: VRF1
    dhcp_address: 10.10.10.10
    state: present
  delegate_to: localhost

- name: Remove DHCP Server at site Network
  cisco.mso.mso_schema_site_network_dhcp_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    network: Network1
    dhcp_vrf: VRF1
    dhcp_address: 10.10.10.10
    state: absent
  delegate_to: localhost

- name: Query DHCP Server a specific site Netwok 
  cisco.mso.mso_schema_site_network_dhcp_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
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
        network=dict(type='str', required=True),
        dhcp_vrf=dict(type='str', required=True),
        dhcp_address=dict(type='str', required=True),
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
    dhcp_vrf = module.params.get('dhcp_vrf')
    dhcp_address = module.params.get('dhcp_address')
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

    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))
    template_idx = templates.index(template)

    vrf_path = '/schemas/{0}/templates/{1}/vrfs/{2}'.format(schema_id, template, dhcp_vrf)


    # Get Network
    network_ref = '/schemas/{schema_id}/templates/{template}/networks/{network}'.format(schema_id=schema_id, template=template, network=network)
    networks = [v.get('nwRef') for v in schema_obj.get('sites')[site_idx]['networks']]
    # networks_name = [mso.dict_from_ref(v).get('name') for v in networks]
    if network_ref not in networks:
        mso.fail_json(msg="Provided Network '{0}' does not exist. Existing Networks: {1}".format(network, ', '.join(networks)))

    network_idx = networks.index(network_ref)


    # Get DCNM Static Leafs
    dhcps = [r.get('dhcpServerAddr') for r in schema_obj.get('sites')[site_idx]['networks'][network_idx]['addrVrf']]
    if dhcp_address is not None and dhcp_address in dhcps:
        dhcp_idx = dhcps.index(dhcp_address)
        dhcp_path = '/sites/{0}/networks/{1}/addrVrf'.format(site_template, network)
        mso.existing = schema_obj.get('sites')[site_idx]['networks'][network_idx]['addrVrf'][dhcp_idx]

    if state == 'query':
        if dhcp_address is None:
            mso.existing = schema_obj.get('sites')[site_idx]['networks'][network_idx]['addrVrf']
        elif not mso.existing:
            mso.fail_json(msg="Switch '{serial}' not found".format(serial=dhcp_address))
        mso.exit_json()

    dhcps_path = '/sites/{0}/networks/{1}/addrVrf'.format(site_template, network)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=dhcp_path))

    elif state == 'present':

        payload = dict(
            dhcpServerAddr=dhcp_address,
            dhcpVrf=vrf_path
        )


        mso.sanitize(payload, collate=True)
        if mso.existing:
            #ops.append(dict(op='replace', path=leaf_path, value=mso.sent))
            mso.exit_json()
        else:
            ops.append(dict(op='add', path=dhcps_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
