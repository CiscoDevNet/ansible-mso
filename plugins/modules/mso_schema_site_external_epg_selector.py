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
module: mso_schema_site_external_epg_selector
short_description: Manage External EPG selector in schema of cloud sites
description:
- Manage External EPG selector in schema of cloud sites on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
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
  external_epg:
    description:
    - The name of the External EPG to be managed.
    type: str
    required: yes
  site:
    description:
    - The name of the cloud site.
    type: str
  selector:
    description:
    - The name of the selector.
    type: str
  ip_address:
    description:
    - The value of the IP Address associated with the selector.
    required: true
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: mso_schema_template_externalepg
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a selector to an External EPG
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: test
    ip_address: 20.0.0.4
    state: present
  delegate_to: localhost

- name: Remove a Selector
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: test
    state: absent
  delegate_to: localhost

- name: Query a specific Selector
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    selector: selector_1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Selectors
  cisco.mso.mso_schema_site_external_epg_selector:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_test
    template: Template1
    site: azure_ansible_test
    external_epg: ext1
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_contractref_spec, issubset, mso_expression_spec_ext_epg


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        site=dict(type='str', required=True),
        external_epg=dict(type='str', required=True),
        selector=dict(type='str'),
        ip_address=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params.get('schema')
    template = module.params.get('template')
    site = module.params.get('site')
    external_epg = module.params.get('external_epg')
    selector = module.params.get('selector')
    ip_address = module.params.get('ip_address')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema_id
    schema_obj = mso.get_obj('schemas', displayName=schema)
    if not schema_obj:
        mso.fail_json(msg="Provided schema '{0}' does not exist".format(schema))

    schema_path = 'schemas/{id}'.format(**schema_obj)
    schema_id = schema_obj.get('id')

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template,
                                                                                                                  templates=', '.join(templates)))

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    sites = [(s.get('siteId'), s.get('templateName')) for s in schema_obj.get('sites')]
    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = '{0}-{1}'.format(site_id, template)

    payload = dict()
    op_path = ''

    # Get External EPG
    ext_epg_ref = mso.ext_epg_ref(schema_id=schema_id, template=template, external_epg=external_epg)
    external_epgs = [e.get('externalEpgRef') for e in schema_obj.get('sites')[site_idx]['externalEpgs']]

    if ext_epg_ref not in external_epgs:
        op_path = '/sites/{0}/externalEpgs/-'.format(site_template)
        payload.update(
            externalEpgRef=dict(
                schemaId=schema_id,
                templateName=template,
                externalEpgName=external_epg,
            )
        )
        payload.update(l3outDn='')
    else:
        external_epg_idx = external_epgs.index(ext_epg_ref)

    # Get Selector
    if not payload:
        selectors = [s.get('name') for s in schema_obj['sites'][site_idx]['externalEpgs'][external_epg_idx]['subnets']]
        if selector in selectors:
            selector_idx = selectors.index(selector)
            selector_path = '/sites/{0}/externalEpgs/{1}/subnets/{2}'.format(site_template, external_epg, selector_idx)
            mso.existing = schema_obj['sites'][site_idx]['externalEpgs'][external_epg_idx]['subnets'][selector_idx]

    selectors_path = '/sites/{0}/externalEpgs/{1}/subnets/-'.format(site_template, external_epg)
    ops = []

    subnets = dict(
        name=selector,
        ip=ip_address,
    )

    if not external_epgs:
        payload['subnets'] = [subnets]
    else:
        payload = subnets
        op_path = selectors_path

    if state == 'query':
        if selector is None:
            mso.existing = schema_obj['sites'][site_idx]['externalEpgs'][external_epg_idx]['subnets']
        elif not mso.existing:
            mso.fail_json(msg="Selector '{selector}' not found".format(selector=selector))
        mso.exit_json()

    mso.previous = mso.existing

    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=selector_path))

    elif state == 'present':

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=selector_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=op_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
