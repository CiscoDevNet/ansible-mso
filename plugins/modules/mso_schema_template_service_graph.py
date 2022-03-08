#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_template_service_graph_entry
short_description: Manage service_graph entries in schema templates
description:
- Manage service_graph entries in schema templates on Cisco ACI Multi-Site.
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
  service_graph:
    description:
    - The name of the service graph to manage.
    - There should be no space in the service graph name. APIC will throw an error if a space is provided in the service graph name.
    - See the C(service_graph_display_name) attribute if you want the display name of the service graph to contain a space.
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
  # entry:
  #   description:
  #   - The service_graph entry name to manage.
  #   type: str
  #   aliases: [ name ]
  # display_name:
  #   description:
  #   - The name as displayed on the MSO web interface.
  #   type: str
  #   aliases: [ entry_display_name ]
  # service_graph_entry_description:
  #   description:
  #   - The description of this service_graph entry.
  #   type: str
  #   aliases: [ entry_description, description ]
  #   default: ''
  # ethertype:
  #   description:
  #   - The ethernet type to use for this service_graph entry.
  #   type: str
  #   choices: [ arp, fcoe, ip, ipv4, ipv6, mac-security, mpls-unicast, trill, unspecified ]
  # ip_protocol:
  #   description:
  #   - The IP protocol to use for this service_graph entry.
  #   type: str
  #   choices: [ eigrp, egp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp, unspecified ]
  # tcp_session_rules:
  #   description:
  #   - A list of TCP session rules.
  #   type: list
  #   elements: str
  #   choices: [ acknowledgement, established, finish, synchronize, reset, unspecified ]
  # source_from:
  #   description:
  #   - The source port range from.
  #   type: str
  # source_to:
  #   description:
  #   - The source port range to.
  #   type: str
  # destination_from:
  #   description:
  #   - The destination port range from.
  #   type: str
  # destination_to:
  #   description:
  #   - The destination port range to.
  #   type: str
  # arp_flag:
  #   description:
  #   - The ARP flag to use for this service_graph entry.
  #   type: str
  #   choices: [ reply, request, unspecified ]
  # stateful:
  #   description:
  #   - Whether this service_graph entry is stateful.
  #   type: bool
  # fragments_only:
  #   description:
  #   - Whether this service_graph entry only matches fragments.
  #   type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_service_graph
notes:
- Due to restrictions of the MSO REST API this module creates service_graphs when needed, and removes them when the last entry has been removed.
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Add a new service_graph entry
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    service_graph: service_graph 1
    state: present
  delegate_to: localhost

- name: Remove a service_graph entry
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    service_graph: service_graph 1
    state: absent
  delegate_to: localhost

- name: Query a specific service_graph entry
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    service_graph: service_graph 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all service_graph entries
  cisco.mso.mso_schema_template_service_graph:
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
        service_graph_name=dict(type='str', required=True),
        service_graph_description=dict(type='str', default=''),
        service_graph_display_name=dict(type='str'),
        service_node_name=dict(type='str'),
        # service_node_type=dict(type='str'),
        # entry=dict(type='str', aliases=['name']),  # This parameter is not required for querying all objects
        # service_graph_entry_description=dict(type='str', default='', aliases=['entry_description', 'description']),
        # display_name=dict(type='str', aliases=['entry_display_name']),
        # ethertype=dict(type='str', choices=['arp', 'fcoe', 'ip', 'ipv4', 'ipv6', 'mac-security', 'mpls-unicast', 'trill', 'unspecified']),
        # ip_protocol=dict(type='str', choices=['eigrp', 'egp', 'icmp', 'icmpv6', 'igmp', 'igp', 'l2tp', 'ospfigp', 'pim', 'tcp', 'udp', 'unspecified']),
        # tcp_session_rules=dict(type='list', elements='str', choices=['acknowledgement', 'established', 'finish', 'synchronize', 'reset', 'unspecified']),
        # source_from=dict(type='str'),
        # source_to=dict(type='str'),
        # destination_from=dict(type='str'),
        # destination_to=dict(type='str'),
        # arp_flag=dict(type='str', choices=['reply', 'request', 'unspecified']),
        # stateful=dict(type='bool'),
        # fragments_only=dict(type='bool'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['service_node_name']],
            ['state', 'present', ['service_node_name']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    service_graph_name = module.params.get('service_graph_name')
    service_graph_display_name = module.params.get('service_graph_display_name')
    service_graph_description = module.params.get('service_graph_description')
    service_node_name = module.params.get('service_node_name')
    # entry = module.params.get('entry')
    # display_name = module.params.get('display_name')
    # service_graph_entry_description = module.params.get('service_graph_entry_description')
    # ethertype = module.params.get('ethertype')
    # ip_protocol = module.params.get('ip_protocol')
    # tcp_session_rules = module.params.get('tcp_session_rules')
    # source_from = module.params.get('source_from')
    # source_to = module.params.get('source_to')
    # destination_from = module.params.get('destination_from')
    # destination_to = module.params.get('destination_to')
    # arp_flag = module.params.get('arp_flag')
    # stateful = module.params.get('stateful')
    # fragments_only = module.params.get('fragments_only')
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

    # Get service graphs
   

    mso.existing = {}
    service_graph_idx = None
    service_node_idx = None
    service_node_index = 1
        
    service_nodes = mso.query_node(service_node_name)
    service_node_id = service_nodes.get('id')
    mso.stdout = "NODEOBJ "+ str(service_nodes) + "\n"

    service_graphs = [f.get('name') for f in schema_obj.get('templates')[template_idx]['serviceGraphs']]
    if service_graph_name in service_graphs:
        service_graph_idx = service_graphs.index(service_graph_name)
        mso.stdout += "GRAPHINDEX "+ str(service_graph_idx) + "\n"

        # Get index value of node in the service graph if the node is present. Updating node is not applicable because same node can be added more than once?
        service_nodes = [f.get('name') for f in schema_obj.get('templates')[template_idx]['serviceGraphs'][service_graph_idx]['serviceNodes']]
        service_node_index = len(service_nodes) + 1
  
    if state == 'query':
        if service_node_name is None:
            if service_graph_idx is None:
                mso.fail_json(msg="service_graph '{service_graph}' not found".format(service_graph=service_graph_name))
            mso.existing = schema_obj.get('templates')[template_idx]['serviceGraphs'][service_graph_idx]['serviceNodes']
        elif not mso.existing:
            mso.fail_json(msg="Service node '{service_node_name}' not found".format(service_node_name=service_node_name))
        mso.exit_json()

    service_graphs_path = '/templates/{0}/serviceGraphs'.format(template)
    service_graph_path = '/templates/{0}/serviceGraphs/{1}'.format(template, service_graph_name)
    service_nodes_path = '/templates/{0}/serviceGraphs/{1}/serviceNodes'.format(template, service_graph_name)
    service_node_path = '/templates/{0}/serviceGraphs/{1}/serviceNodes/{2}'.format(template, service_graph_name, service_node_name)
    ops = []

    mso.previous = mso.existing
    if state == 'absent':
        mso.proposed = mso.sent = {}

        if service_graph_idx is None:
            # There was no service graph to begin with
            pass
        elif service_node_idx is None:
            # There was no service node to begin with
            pass
        elif len(service_nodes) == 1:
            # There is only one service node, remove service graph
            mso.existing = {}
            ops.append(dict(op='remove', path=service_graph_path))

        else:
            mso.existing = {}
            ops.append(dict(op='remove', path=service_node_path))

    elif state == 'present':

        payload = dict(
          name=service_node_name,
          index=service_node_index,
          serviceNodeTypeId=service_node_id,
          serviceNodeRef=dict(   
            serviceNodeName=service_node_name,
                  serviceGraphName=service_graph_name,
                  templateName=template,
                  schemaId=schema_id,
            ),
        )

        mso.sanitize(payload, collate=True)

        if service_graph_idx is None:
            # service graph does not exist, so we have to create it
            if service_graph_display_name is None:
                service_graph_display_name = service_graph_name
            #service_graph_ref = mso.service_graph_ref(schema_id=schema_id,template=template, service_graph=service_graph_name)

            payload = dict(
                name=service_graph_name,
                displayName=service_graph_display_name,
                description=service_graph_description,
                serviceGraphRef=dict(
                  serviceGraphName=service_graph_name,
                  templateName=template,
                  schemaId=schema_id,
            ),
                serviceNodes=[mso.sent],
            )

            mso.sanitize(payload, collate=True)

            mso.stdout += "SERVICEGRAPHSPATH" + str(payload) + "\n"
            ops.append(dict(op='add', path=service_graphs_path + '/-', value=payload))

        elif service_node_idx is None:
            # Service node does not exist, so we have to add it
            mso.stdout += "SERVICENODESPATH" + str(mso.sent) + "\n"
            ops.append(dict(op='add', path=service_nodes_path + '/-', value=mso.sent))

        else:
            # Service node exists, we have to update it
            for (key, value) in mso.sent.items():
                ops.append(dict(op='replace', path=service_node_path + '/' + key, value=value))

        mso.existing = mso.proposed

    if not module.check_mode:
        #mso.stdout = "PATHS" 
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
