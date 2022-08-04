#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_schema_site_contract_service_graph
short_description: Manage the service graph association with a contract in schema sites
description:
- Manage the service graph association with a contract in schema sites on Cisco ACI Multi-Site.
- The Contract Service Graph parameter is supported on versions of MSO/NDO that are 3.3 or greater.
author:
- Cindy Zhao (@cizhao)
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
  contract:
    description:
    - The name of the contract.
    type: str
    required: yes
  service_graph:
    description:
    - The service graph to associate with this contract.
    type: str
  service_graph_template:
    description:
    - The template name in which the service graph is located.
    type: str
  service_graph_schema:
    description:
    - The schema name in which the service graph is located.
    type: str
  service_nodes:
    description:
    - A list of nodes and their connector details associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      provider_cluster_interface:
        description:
        - The name of the cluster interface for provider connector.
        required: true
        type: str
      provider_redirect_policy:
        description:
        - Redirect policy for provider connector.
        type: str
      consumer_cluster_interface:
        description:
        - The name of the cluster interface for consumer connector.
        required: true
        type: str
      consumer_redirect_policy:
        description:
        - Redirect policy for consumer connector.
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_service_graph
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_contract_service_graph_spec


def main():

    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type='str', required=True),
        site=dict(type='str', required=True),
        template=dict(type='str', required=True),
        contract=dict(type='str', required=True),
        service_graph=dict(type='str'),
        service_graph_template=dict(type='str'),
        service_graph_schema=dict(type='str'),
        service_nodes=dict(type='list', elements='dict', options=mso_contract_service_graph_spec()),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['service_graph']],
            ['state', 'present', ['service_graph', 'service_nodes']],
        ],
    )

    schema = module.params.get('schema')
    template = module.params.get('template').replace(' ', '')
    site = module.params.get('site')
    contract = module.params.get('contract')
    service_graph = module.params.get('service_graph')
    service_graph_template = module.params.get('service_graph_template')
    service_graph_schema = module.params.get('service_graph_schema')
    service_nodes = module.params.get('service_nodes')

    state = module.params.get('state')

    mso = MSOModule(module)

        # Initialize variables
    ops = []
    service_graph_ref = ""

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = schema_obj.get('templates')
    template_names = [t.get('name') for t in templates]
    if template not in template_names:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=', '.join(template_names)))
    
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

    contract_service_graph_path = '/sites/{0}/contracts/{1}/serviceGraphRelationship'.format(site_template, contract)
    contract_ref = '/schemas/{0}/templates/{1}/contracts/{2}'.format(schema_id, template, contract)
    if service_graph and service_graph_schema and service_graph_template:
        service_graph_schema_id, _, _ = mso.query_schema(service_graph_schema)
        service_graph_ref = "/schemas/{0}/templates/{1}/serviceGraphs/{2}".format(service_graph_schema_id, service_graph_template, service_graph)

    # Get contracts at site level
    contracts = schema_obj.get('sites')[site_idx]['contracts']
    contract_obj = next((item for item in contracts if item.get("contractRef") == contract_ref))
    if contract_obj:
        # Get service graph if it exists in contract
        if contract_obj.get("serviceGraphRelationship"):
            service_obj = contract_obj.get("serviceGraphRelationship")
            contract_service_graph_ref = service_obj.get("serviceGraphRef")
            contract_service_nodes_relationship = service_obj.get("serviceNodesRelationship")
            if service_graph_ref == "" or service_graph_ref == contract_service_graph_ref:
                mso.update_site_service_graph_obj(service_obj)
                mso.existing = service_obj

    else:
        mso.fail_json(msg="Provided contract '{0}' does not exist. Existing contracts: {1}".format(
            contract, ', '.join([c.get('name') for c in contracts])))

    if state == "query":

        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            ops.append(dict("remove", path=contract_service_graph_path))

    elif state == "present":
        # Validation to check if amount of service graph nodes provided is matching the contract service graph.
        if mso.existing:
            contract_service_nodes = mso.existing.get("serviceNodesRelationship")
            if len(contract_service_nodes) != len(service_nodes):
                mso.fail_json(msg="Number of service graph nodes provided is inconsistent with current service graph")
            if mso.existing.get("serviceGraphRef") != service_graph_ref:
                mso.fail_json(msg="Sevice graph '{0}' is not attached to contract {1}.".format(service_graph, contract))

        service_nodes_relationship = []
        contract_service_graph_payload = dict(
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=service_graph_template,
                schemaId=service_graph_schema_id
            ),
            serviceNodesRelationship=service_nodes_relationship
        )
        for node_id, service_node in enumerate(contract_service_nodes_relationship):
            contract_service_node = mso.dict_from_ref(service_node.get("serviceNodeRef"))
            service_nodes_relationship.append(
                {
                    'serviceNodeRef': contract_service_node,
                    'providerConnector': {
                        'clusterInterface': {
                          'dn': service_nodes[node_id].get("provider_cluster_interface")
                        },
                        'redirectPolicy': {
                          'dn': service_nodes[node_id].get("provider_redirect_policy")
                        }
                    },
                    'consumerConnector': {
                        'clusterInterface': {
                          'dn': service_nodes[node_id].get("consumer_cluster_interface")
                        },
                        'redirectPolicy': {
                          'dn': service_nodes[node_id].get("consumer_redirect_policy")
                        }
                    },
                }
            )


        if mso.existing:
            if contract_obj.get("serviceGraphRelationship")["serviceGraphRef"] != service_graph_ref:
                mso.fail_json(msg="Sevice graph '{0}' is not attached to contract {1}.".format(service_graph, contract))
            ops.append(dict(op='replace', path=contract_service_graph_path, value=contract_service_graph_payload))
        else:
            ops.append(dict(op='add', path=contract_service_graph_path, value=contract_service_graph_payload))

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()


