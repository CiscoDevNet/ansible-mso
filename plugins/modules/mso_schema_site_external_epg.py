#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_external_epg
short_description: Manage External EPG in schema of sites
description:
- Manage External EPG in schema of sites on Cisco ACI Multi-Site.
- This module can only be used on versions of MSO that are 3.3 or greater.
author:
- Anvitha Jain (@anvitha-jain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: yes
  template:
    description:
    - The name of the template to change.
    type: str
    required: yes
  l3out:
    description:
    - The L3Out associated with the external epg.
    type: str
  external_epg:
    description:
    - The name of the External EPG to be managed.
    type: str
    aliases: [ name ]
  site:
    description:
    - The name of the site.
    type: str
    required: yes
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_external_epg
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
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
        site=dict(type='str', required=True),
        l3out=dict(type='str'),
        external_epg=dict(type='str', aliases=['name']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['external_epg']],
            ['state', 'present', ['external_epg', 'l3out']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template')
    site = module.params.get('site')
    external_epg = module.params.get('external_epg')
    l3out = module.params.get('l3out')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema_id
    schema_obj = mso.get_obj('schemas', displayName=schema)
    if not schema_obj:
        mso.fail_json(msg="Provided schema '{0}' does not exist.".format(schema))

    schema_path = 'schemas/{id}'.format(**schema_obj)
    schema_id = schema_obj.get('id')

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template:
        if template in templates:
            template_idx = templates.index(template)
            path = 'tenants/{0}'.format(schema_obj.get('templates')[template_idx]['tenantId'])
            tenant_name = mso.request(path, method='GET').get('name')
    else:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template,
                                                                                                                  templates=', '.join(templates)))

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if 'sites' not in schema_obj:
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get('siteId'), s.get('templateName')) for s in schema_obj.get('sites')]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ', '.join(templates)))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = '{0}-{1}'.format(site_id, template)

    payload = dict()
    op_path = '/sites/{0}/externalEpgs/-'.format(site_template)

    # Get External EPG
    ext_epg_ref = mso.ext_epg_ref(schema_id=schema_id, template=template, external_epg=external_epg)
    external_epgs = [e.get('externalEpgRef') for e in schema_obj.get('sites')[site_idx]['externalEpgs']]

    if ext_epg_ref in external_epgs:
        external_epg_idx = external_epgs.index(ext_epg_ref)
        # Get External EPG
        mso.existing = schema_obj['sites'][site_idx]['externalEpgs'][external_epg_idx]
        op_path = '/sites/{0}/externalEpgs/{1}'.format(site_template, external_epg)

    ops = []

    if state == 'query':
        if external_epg is None:
            mso.existing = schema_obj.get('sites')[site_idx]['externalEpgs']
        elif not mso.existing:
            mso.fail_json(msg="External EPG '{external_epg}' not found".format(external_epg=external_epg))
        mso.exit_json()

    mso.previous = mso.existing

    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=op_path))

    elif state == 'present':
        l3out_dn = 'uni/tn-{0}/out-{1}'.format(tenant_name, l3out)
        payload = dict(
            externalEpgRef=dict(
                schemaId=schema_id,
                templateName=template,
                externalEpgName=external_epg,
            ),
            l3outDn=l3out_dn,
            l3outRef=dict(
                schemaId=schema_id,
                templateName=template,
                l3outName=l3out,
            ),
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=op_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=op_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
