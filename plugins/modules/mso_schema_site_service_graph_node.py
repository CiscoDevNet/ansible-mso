#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_service_graph_node
short_description: Manage Service Graph in schema sites
description:
- Manage Service Graph in schema sites on Cisco ACI Multi-Site.
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
    - The name of the template.
    type: str
    required: yes
  site:
    description:
    - The name of the site.
    type: str
    required: yes
  tenant:
    description:
    - The name of the tenant.
    type: str
  service_graph:
    description:
    - The name of the Service Graph to manage.
    type: str
    aliases: [ name ]
  devices:
    description:
    - A list of devices to be associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the device
        required: true
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
- name: Add a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    tenant: tenant1
    devices:
      - name: ansible_test_firewall
      - name: ansible_test_adc
      - name: ansible_test_other
    state: present
  delegate_to: localhost

- name: Remove a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: absent
  delegate_to: localhost

- name: Query a specific Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: query
  delegate_to: localhost

- name: Query all Service Graphs
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    site: site1
    state: query
  delegate_to: localhost
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_service_graph_node_device_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        service_graph=dict(type='str', aliases=['name']),
        tenant=dict(type='str'),
        site=dict(type='str', required=True),
        devices=dict(type='list', elements='dict', options=mso_service_graph_node_device_spec()),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['service_graph']],
            ['state', 'present', ['service_graph', 'devices']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    service_graph = module.params.get('service_graph')
    devices = module.params.get('devices')
    site = module.params.get('site')
    tenant = module.params.get('tenant')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t for t in schema_obj.get('templates')]
    template_names = [t.get('name') for t in templates]
    if template not in template_names:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template,
                                                                                                                  templates=', '.join(template_names)))
    template_idx = template_names.index(template)

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

    mso.existing = {}
    service_graph_idx = None

    # Get Service Graph
    service_graph_ref = mso.service_graph_ref(schema_id=schema_id, template=template, service_graph=service_graph)
    service_graph_refs = [f.get('serviceGraphRef') for f in schema_obj.get('sites')[site_idx]['serviceGraphs']]
    if service_graph is not None and service_graph_ref in service_graph_refs:
        service_graph_idx = service_graph_refs.index(service_graph_ref)
        mso.existing = schema_obj.get('sites')[site_idx]['serviceGraphs'][service_graph_idx]

    if state == 'query':
        if service_graph is None:
            mso.existing = schema_obj.get('sites')[site_idx]['serviceGraphs']
        if service_graph is not None and service_graph_idx is None:
            mso.fail_json(msg="Service Graph '{service_graph}' not found".format(service_graph=service_graph))
        mso.exit_json()

    service_graphs_path = '/sites/{0}/serviceGraphs/-'.format(site_template)
    service_graph_path = '/sites/{0}/serviceGraphs/{1}'.format(site_template, service_graph)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=service_graph_path))

    elif state == 'present':
        devices_payload = []
        node_device_type = []
        device_types = {}
        device_number = 0
        service_graphs = [f for f in templates[template_idx]['serviceGraphs']]
        service_nodes_list = [r['serviceNodes'] for r in service_graphs if r.get('name') == service_graph]
        service_nodes_list_types = [k.get('name') for k in service_nodes_list[0]]
        user_number_devices = len(devices)
        number_service_nodes = len(service_nodes_list[0])
        if user_number_devices != number_service_nodes:
            mso.fail_json(msg="Service Graph '{0}' has '{1}' service node type(s) but '{2}' service node type(s) were given for the device"
                          .format(service_graph, number_service_nodes, user_number_devices))
        # Populate dict for service node type and device type
        for node_type in service_nodes_list_types:
            if node_type == 'firewall':
                node_device_type.append('FW')
            elif node_type == 'load-balancer':
                node_device_type.append('ADC')
            else:
                node_device_type.append('OTHERS')

        # Populate dict for device types and an index number
        keys_number_devices = range(user_number_devices)
        for number in keys_number_devices:
            device_types[number] = node_device_type[number]

        if devices is not None:
            for device in devices:
                device_name = device.get('name')
                query_device_data = mso.query_service_node_device_types(site_id, tenant, device_types[device_number], device_name)
                device_names = [f.get('name') for f in query_device_data]
                service_node_type = node_device_type[device_number]
                device_number = device_number + 1
                device_names = [f.get('name') for f in query_device_data]
                if device_name not in device_names:
                    mso.fail_json(msg="Provided device '{0}' of type '{1}' does not exist."
                                  .format(device_name, service_node_type))
                else:
                    for device_data in query_device_data:
                        if device_data['name'] == device_name:
                            devices_payload.append(dict(
                                device=dict(
                                    dn=device_data.get('dn'),
                                    funcTyp=device_data.get('funcType'),
                                ),
                                serviceNodeRef=dict(
                                    serviceNodeName=service_node_type,
                                    serviceGraphName=service_graph,
                                    templateName=template,
                                    schemaId=schema_id,
                                )
                            ),
                            )

        payload = dict(
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=template,
                schemaId=schema_id,
            ),
            serviceNodes=devices_payload,
        )

        mso.sanitize(payload, collate=True)

        if not mso.existing:
            ops.append(dict(op='add', path=service_graphs_path, value=payload))
        else:
            ops.append(dict(op='replace', path=service_graph_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
