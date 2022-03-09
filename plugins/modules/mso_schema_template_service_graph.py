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
module: mso_schema_template_service_graph
short_description: Manage service graph in schema templates
description:
- Manage service graphs in schema templates on Cisco ACI Multi-Site.
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
  service_graph_name:
    description:
    - The name of the service graph to manage.
    type: str
    required: yes
  service_graph_description:
    description:
    - The description of service graph.
    type: str
    default: ''
  service_graph_display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  service_node_list:
    description:
    - A list of nodes to be associated with the service graph.
    type: list
    suboptions:
      type:
        description:
        - The type of node
        required: true
        type: str
        aliases: [ name ]
  node_filter:
   description:
    - The filter for the node.
    type: str
    choices: [ allow-all, filters-from-contract ]
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
- name: Add a new service graph 
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    service_node_list: 
      - type: firewall
      - type: other
      - type: load-balancer
    state: present
  delegate_to: localhost

- name: Remove a service graph
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    state: absent
  delegate_to: localhost

- name: Query a specific service graph
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    state: query
  delegate_to: localhost

- name: Query all service graphs
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    state: query
  delegate_to: localhost
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_node_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        template=dict(type='str', required=True),
        service_graph_name=dict(type='str'),
        service_graph_description=dict(type='str', default=''),
        service_graph_display_name=dict(type='str'),
        service_node_list=dict(type='list',dict='elements', options=mso_node_spec()),
        node_filter=dict(type='str', choices=['allow-all', 'filters-from-contract']),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['service_graph_name']],
            ['state', 'present', ['service_graph_name', 'service_node_list']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    service_graph_name = module.params.get('service_graph_name')
    service_graph_display_name = module.params.get('service_graph_display_name')
    service_graph_description = module.params.get('service_graph_description')
    service_node_list = module.params.get('service_node_list')
    node_filter = module.params.get('node_filter')
    state = module.params.get('state')

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get('name') for t in schema_obj.get('templates')]
    if template not in templates:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template,
                                                                                                                  templates=', '.join(templates)))
    template_idx = templates.index(template)

    mso.existing = {}
    service_graph_idx = None
    index = 0
    Nodes = []

    # Get service graphs
    service_graphs = [f.get('name') for f in schema_obj.get('templates')[template_idx]['serviceGraphs']]
    if service_graph_name in service_graphs:
        service_graph_idx = service_graphs.index(service_graph_name)
    
    # Get service nodes
    query_node_data = mso.query_nodes()
    service_nodes = [f.get('name') for f in query_node_data]
    if service_node_list is not None:
      for node in service_node_list:
        node_name = node.get('type')
        if node_name in service_nodes:
          index = index + 1
          for node_data in query_node_data:
            if node_data['name'] == node_name:
              node_data = node_data
          Nodes.append(dict(
              name=node_name,
              serviceNodeTypeId=node_data.get('id'),
              index = index,
              serviceNodeRef=dict(   
                serviceNodeName=node_name,
                serviceGraphName=service_graph_name,
                templateName=template,
                schemaId=schema_id,
          )),
          )
  
    if state == 'query':
      if service_graph_name is None:
            mso.existing = schema_obj.get('templates')[template_idx]['serviceGraphs']
      if service_graph_name is not None and service_graph_idx is None:
            mso.fail_json(msg="service_graph '{service_graph}' not found".format(service_graph=service_graph_name))
      elif service_graph_idx is not None:
            mso.existing = schema_obj.get('templates')[template_idx]['serviceGraphs'][service_graph_idx]
      mso.exit_json()

    service_graphs_path = '/templates/{0}/serviceGraphs'.format(template)
    service_graph_path = '/templates/{0}/serviceGraphs/{1}'.format(template, service_graph_name)
    service_nodes_path = '/templates/{0}/serviceGraphs/{1}/serviceNodes'.format(template, service_graph_name)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        mso.proposed = mso.sent = {}
        if service_graph_idx is None:
            # There was no service graph to begin with
            pass
        else:
            mso.existing = {}
            ops.append(dict(op='remove', path=service_graph_path))

    elif state == 'present':
        mso.sanitize(Nodes, collate=True)
        if service_graph_idx is None:
            # service graph does not exist, so we have to create it
            if service_graph_display_name is None:
                service_graph_display_name = service_graph_name

            payload = dict(
                name=service_graph_name,
                displayName=service_graph_display_name,
                description=service_graph_description,
                nodeFilter=node_filter,
                serviceGraphRef=dict(
                  serviceGraphName=service_graph_name,
                  templateName=template,
                  schemaId=schema_id,
            ),
                serviceNodes=mso.sent,
            )

            mso.sanitize(payload, collate=True)
            ops.append(dict(op='add', path=service_graphs_path + '/-', value=payload))

        else:
            ops.append(dict(op='replace', path=service_nodes_path , value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
