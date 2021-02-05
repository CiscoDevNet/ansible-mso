#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_bd_subnet
short_description: Manage site-local BD subnets in schema template
description:
- Manage site-local BD subnets in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
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
  bd:
    description:
    - The name of the BD.
    type: str
    required: true
    aliases: [ name ]
  subnet:
    description:
    - The IP range in CIDR notation.
    type: str
    aliases: [ ip ]
  description:
    description:
    - The description of this subnet.
    type: str
  scope:
    description:
    - The scope of the subnet.
    type: str
    default: private
    choices: [ private, public ]
  shared:
    description:
    - Whether this subnet is shared between VRFs.
    type: bool
    default: false
  no_default_gateway:
    description:
    - Whether this subnet has a default gateway.
    type: bool
    default: false
  querier:
    description:
    - Whether this subnet is an IGMP querier.
    type: bool
    default: false
  is_virtual_ip:
    description:
    - Treat as Virtual IP Address
    type: bool
    default: false
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing on object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_bd
- module: cisco.mso.mso_schema_template_bd
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a new site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: present
  delegate_to: localhost

- name: Remove a site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: absent
  delegate_to: localhost

- name: Query a specific site BD subnet
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    subnet: 11.11.11.0/24
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all site BD subnets
  cisco.mso.mso_schema_site_bd_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    bd: BD1
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_subnet_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(mso_subnet_spec())
    argument_spec.update(
        schema=dict(type='str', required=True),
        site=dict(type='str', required=True),
        template=dict(type='str', required=True),
        bd=dict(type='str', aliases=['name'], required=True),
        subnet=dict(type='str', aliases=['ip']),
        description=dict(type='str'),
        scope=dict(type='str', default='private', choices=['private', 'public']),
        shared=dict(type='bool', default=False),
        no_default_gateway=dict(type='bool', default=False),
        querier=dict(type='bool', default=False),
        is_virtual_ip=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['subnet']],
            ['state', 'present', ['subnet']],
        ],
    )

    schema = module.params.get('schema')
    site = module.params.get('site')
    template = module.params.get('template').replace(' ', '')
    bd = module.params.get('bd')
    subnet = module.params.get('subnet')
    description = module.params.get('description')
    scope = module.params.get('scope')
    shared = module.params.get('shared')
    no_default_gateway = module.params.get('no_default_gateway')
    querier = module.params.get('querier')
    is_virtual_ip = module.params.get('is_virtual_ip')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))
    template_idx = templates.index(template)

    # Get template BDs
    template_bds = [b.get('name') for b in schema_obj.get('templates')[template_idx]['bds']]

    # Get template BD
    if bd not in template_bds:
        mso.fail_json(msg="Provided BD '{0}' does not exist. Existing template BDs: {1}".format(bd, ', '.join(template_bds)))
    template_bd_idx = template_bds.index(bd)
    template_bd = schema_obj.get('templates')[template_idx]['bds'][template_bd_idx]
    if template_bd.get('l2Stretch') is True and state == 'present':
        mso.fail_json(
            msg="The l2Stretch of template bd should be false in order to create a site bd subnet. Set l2Stretch as false using mso_schema_template_bd"
        )

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if 'sites' not in schema_obj:
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get('siteId'), s.get('templateName')) for s in schema_obj.get('sites')]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site/template '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = '{0}-{1}'.format(site_id, template)

    # Get BD
    bd_ref = mso.bd_ref(schema_id=schema_id, template=template, bd=bd)
    bds = [v.get('bdRef') for v in schema_obj.get('sites')[site_idx]['bds']]
    if bd_ref not in bds:
        mso.fail_json(msg="Provided BD '{0}' does not exist. Existing site BDs: {1}".format(bd, ', '.join(bds)))
    bd_idx = bds.index(bd_ref)

    # Get Subnet
    subnets = [s.get('ip') for s in schema_obj.get('sites')[site_idx]['bds'][bd_idx]['subnets']]
    if subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = '/sites/{0}/bds/{1}/subnets/{2}'.format(site_template, bd, subnet_idx)
        mso.existing = schema_obj.get('sites')[site_idx]['bds'][bd_idx]['subnets'][subnet_idx]

    if state == 'query':
        if subnet is None:
            mso.existing = schema_obj.get('sites')[site_idx]['bds'][bd_idx]['subnets']
        elif not mso.existing:
            mso.fail_json(msg="Subnet IP '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = '/sites/{0}/bds/{1}/subnets'.format(site_template, bd)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=subnet_path))

    elif state == 'present':
        if not mso.existing:
            if description is None:
                description = subnet

        payload = dict(
            ip=subnet,
            description=description,
            scope=scope,
            shared=shared,
            noDefaultGateway=no_default_gateway,
            virtual=is_virtual_ip,
            querier=querier,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=subnet_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=subnets_path + '/-', value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
