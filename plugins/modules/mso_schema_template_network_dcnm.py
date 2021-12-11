#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Cassio Lange (calange) <calange@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_network_dcnm
short_description: Manage DCNM VRFs in schema templates
description:
- Manage VRFs in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Cassio Lange (@calange)
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
  network:
    description:
    - The name of the network to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  network_id:
    description:
    - Specify the network ID or leave the field empty and the ID will be automatically allocated 
    type: int
  layer2_only:
    description:
    - Choose whether or not this is a Layer2 Only network
    type: bool
  vrf:
    description:
    - The VRF associated to this BD. This is required only when creating a new BD.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current template.
        type: str
  network_profile:
    description:
    - Choose Network Profile
    type: str
    default: Default_Network_Universal
  network_extension_profile:
    description:
    - Choose Network Profile
    type: str
    default: Default_Network_Extension_Universal
  vlan_name:
    description:
    - Vlan Name
    type: str
  vlan_id:
    description:
    - Vland ID
    type: int
  gateway_ip:
    description:
    - Gateway IP and subnet
  type: str
  suppress_arp:
    description:
    - Choose whether you want to Suppress ARP.
  type: bool 
  svi_description:
    description:
    - SVI Description
  type: str
  mtu:
    description:
    - Provide the MTU for this network.
  type: int 
  default: 9216
  routing_tag:
    description:
    - Provide the Routing Tag.
  type: int
  default: 12345
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
- name: Add a new VRF
  cisco.mso.mso_schema_template_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    network: Network 1
    vrf:
      name: VRF1
      schema: Schema Origin
      template: Template Origin
    state: present
  delegate_to: localhost

- name: Remove an VRF
  cisco.mso.mso_schema_template_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    network: Network 1
    state: absent
  delegate_to: localhost

- name: Query a specific VRFs
  cisco.mso.mso_schema_template_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    network: Network 1 
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VRFs
  cisco.mso.mso_schema_template_network_dcnm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec,  mso_reference_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        network=dict(type='str', aliases=['name'], required=True),
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        display_name=dict(type='str'),
        network_id=dict(type='int'),
        layer2_only=dict(type='bool'),
        vrf=dict(type='dict', required=True, options=mso_reference_spec()),
        network_profile=dict(type='str', default='Default_Network_Universal'),
        network_extension_profile=dict(type='str', default='Default_Network_Extension_Universal'),
        vlan_name=dict(type='str'),
        vlan_id=dict(type='int'),
        gateway_ip=dict(type='str', required=True),
        suppress_arp=dict(type='bool', default=False),
        svi_description=dict(type='str'),
        mtu=dict(type='int', default='9216'),
        routing_tag=dict(type='int', default='12345'),
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

    network = module.params.get('network')
    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    vrf = module.params.get('vrf')
    if vrf is not None and vrf.get('template') is not None:
        vrf['template'] = vrf.get('template').replace(' ', '')
    display_name = module.params.get('display_name')
    network_id = module.params.get('network_id')
    layer2_only = module.params.get('layer2_only')
    network_profile = module.params.get('network_profile')
    network_extension_profile = module.params.get('network_extension_profile')
    vlan_name = module.params.get('vlan_name')
    vlan_id = module.params.get('vlan_id')
    gateway_ip = module.params.get('gateway_ip')
    suppress_arp = module.params.get('suppress_arp')
    svi_description = module.params.get('svi_description')
    mtu = module.params.get('mtu')
    routing_tag = module.params.get('routing_tag')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))
    template_idx = templates.index(template)

    networks = [n.get('name') for n in schema_obj.get('templates')[template_idx]['networks']]

    if network is not None and network in networks:
        networks_idx = networks.index(network)
        mso.existing = schema_obj.get('templates')[template_idx]['networks'][networks_idx]

    if state == 'query':
        if network is None:
            mso.existing = schema_obj.get('templates')[template_idx]['network']
        elif not mso.existing:
            mso.fail_json(msg="VRF '{network}' not found".format(network=network))
        mso.exit_json()

    networks_path = '/templates/{0}/networks'.format(template)
    network_path = '/templates/{0}/networks/{1}'.format(template, network)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=network_path))

    elif state == 'present':
        if display_name is None and not mso.existing:
            display_name = network
        vrf_ref = mso.make_reference(vrf, 'vrf', schema_id, template)


        payload = dict(
            name=network,
            displayName=display_name,
            vrfRef=vrf_ref,
            nwId=network_id,
            l2Only=layer2_only,
            nwProfileName=network_profile,
            nwExtnProfileName=network_extension_profile,
            suppressArp=suppress_arp,
            sviDescr=svi_description,
            mtu=mtu,
            tag=routing_tag,
            vlanId=vlan_id,
            vlanName=vlan_name,
            subnets= []
        )
        if gateway_ip is not None:
            payload['subnets'].append(
                {
                    'ip': gateway_ip,
                    'primary':True,
                }
            )

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
