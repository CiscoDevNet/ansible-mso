#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Cassio Lange (calange) <calange@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_vrf_dncm
short_description: Manage DCNM VRFs in schema templates
description:
- Manage VRFs in schema templates on Cisco ACI Multi-Site.
author:
- Cassio Lange (calange)
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
  vrf:
    description:
    - The name of the VRF to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  vrf_id:
    description:
    - Specify the VNI of the VRF or leave the field empty and the VNI will be automatically allocated
    type: int
  vrf_profile:
    description:
    - Specify VRF Profile
    type: str
    default: Default_VRF_Universal
  vrf_extension_profile:
    description:
    - Specify VRF Extension Profile
    type: str
    default: Default_VRF_Extension_Universal
  loopback_routing_tag:
    description:
    - Specify tag is associated with the IP prefix
    type: int
    default: 12345
  redistribute_direct_route_map:
    description:
    - Specifies the route map name for redistribution of routes in the VRF.
    type: str
    default: FABRIC-RMAP-REDIST-SUBNET
  disable_rt_auto_generate:
    description:
    - Disable RT Generate 
    type: bool
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
  cisco.mso.mso_schema_template_vrf_dncm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    state: present
  delegate_to: localhost

- name: Remove an VRF
  cisco.mso.mso_schema_template_vrf_dncm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: absent
  delegate_to: localhost

- name: Query a specific VRFs
  cisco.mso.mso_schema_template_vrf_dncm:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VRFs
  cisco.mso.mso_schema_template_vrf_dncm:
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        vrf=dict(type='str', aliases=['name']),
        display_name=dict(type='str'),
        vrf_id=dict(type='int'),
        vrf_profile=dict(type='str', default='Default_VRF_Universal'),
        vrf_extension_profile=dict(type='str', default='Default_VRF_Extension_Universal'),
        loopback_routing_tag=dict(type='int', default='12345'),
        redistribute_direct_route_map=dict(type='str', default='FABRIC-RMAP-REDIST-SUBNET'),
        disable_rt_auto_generate=dict(type='bool'),
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
    template = module.params.get('template').replace(' ', '')
    vrf = module.params.get('vrf')
    display_name = module.params.get('display_name')
    vrf_id = module.params.get('vrf_id')
    vrf_profile = module.params.get('vrf_profile')
    vrf_extension_profile = module.params.get('vrf_extension_profile')
    loopback_routing_tag = module.params.get('loopback_routing_tag')
    redistribute_direct_route_map = module.params.get('redistribute_direct_route_map')
    disable_rt_auto_generate = module.params.get('disable_rt_auto_generate')  
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))
    template_idx = templates.index(template)

    # Get ANP
    vrfs = [v.get('name') for v in schema_obj.get('templates')[template_idx]['vrfs']]

    if vrf is not None and vrf in vrfs:
        vrf_idx = vrfs.index(vrf)
        mso.existing = schema_obj.get('templates')[template_idx]['vrfs'][vrf_idx]

    if state == 'query':
        if vrf is None:
            mso.existing = schema_obj.get('templates')[template_idx]['vrfs']
        elif not mso.existing:
            mso.fail_json(msg="VRF '{vrf}' not found".format(vrf=vrf))
        mso.exit_json()

    vrfs_path = '/templates/{0}/vrfs'.format(template)
    vrf_path = '/templates/{0}/vrfs/{1}'.format(template, vrf)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=vrf_path))

    elif state == 'present':
        if display_name is None and not mso.existing:
            display_name = vrf

        payload = dict(
            name=vrf,
            displayName=display_name,
            vrfId=vrf_id,
            vrfProfileName=vrf_profile,
            vrfExtnProfileName=vrf_extension_profile,
            tag=loopback_routing_tag,
            redisDirRouteMap=redistribute_direct_route_map,
            rtAutoDisabled=disable_rt_auto_generate
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=vrf_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=vrfs_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
