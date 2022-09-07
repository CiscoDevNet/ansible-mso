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
      index:
        description:
        - The index of the cloud device.
        type: int
      listeners:
        description:
        - Listeners for cloud load balancer.
        type: list
        elements: dict
        suboptions:
          name:
            description:
            - Name of the listener.
            type: str
            required: true
          protocol:
            description:
            - Protocol of the listener.
            type: str
            choices: [ https, tls, inherit, tcp, udp, http ]
            default: tcp
          port:
            description:
            - Port of the listener.
            type: int
            default: 80
          rules:
            description:
            - Rules of the listener.
            type: list
            elements: dict
            suboptions:
              name:
                description:
                - Name of the listener rule.
                type: str
                default: default
              action_type:
                description:
                - Action type of the listener rule.
                type: str
                choices: [ fixedResponse, forward, redirect, haPort ]
                default: forward
              protocol:
                description:
                - Protocol of listener rule.
                type: str
                choices: [ https, tls, inherit, tcp, udp, http ]
                default: tcp
              port:
                description:
                - Port of listener rule.
                type: int
                default: 80
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
    contract_service_graph_path = ""
    payload = {}
    contract_obj = {}

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = schema_obj.get('templates')
    template_names = [t.get('name') for t in templates]
    if template not in template_names:
        mso.fail_json(msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=', '.join(template_names)))

    template_idx = template_names.index(template)

    # Get site
    site_obj = mso.query_site(site)
    
    # Get site id
    site_id = site_obj.get('id')

    # Get site type
    site_type = mso.lookup_site_type(site_obj)

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

    # Get contract
    contract_service_graph_path = '/sites/{0}/contracts/{1}/serviceGraphRelationship'.format(site_template, contract)
    contracts = schema_obj.get('sites')[site_idx]['contracts']
    contracts_in_site = [item.get('contractRef') for item in contracts]
    contract_ref = '/schemas/{0}/templates/{1}/contracts/{2}'.format(schema_id, template, contract)
    contracts_in_temp = [item.get('name') for item in schema_obj['templates'][template_idx]['contracts']]
    if contract not in contracts_in_temp:
        mso.fail_json(msg="Provided contract '{0}' does not exist. Existing contracts: {1}".format(contract, ', '.join(contracts_in_temp)))
    # Get contract at template level
    template_contract_idx = contracts_in_temp.index(contract)
    template_contract_obj = schema_obj['templates'][template_idx]['contracts'][template_contract_idx]
    # Get service graph attached to contract if there is any at template level
    template_contract_service_graph = template_contract_obj.get('serviceGraphRelationship')
    if template_contract_service_graph is None:
        mso.fail_json(msg="No service graph attached to contract {0}.".format(contract))
    if service_graph:
        if service_graph_schema is None:
            service_graph_schema = schema
        if service_graph_template is None:
            service_graph_template = template
        service_graph_schema_id, _, _ = mso.query_schema(service_graph_schema)
        service_graph_ref = "/schemas/{0}/templates/{1}/serviceGraphs/{2}".format(service_graph_schema_id, service_graph_template, service_graph)

    # If contract not at site level but exists at template level
    if contract_ref not in contracts_in_site:
        payload = dict(
            contractRef=dict(
                schemaId=schema_id,
                templateName=template,
                contractName=contract,
            )
        )
    else:
        # Get contract existing at site level
        site_contract_idx = contracts_in_site.index(contract_ref)
        contract_obj = contracts[site_contract_idx]

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
                mso.fail_json(msg="Provided service graph {0} is not attached to given contract {1} at site level. Existing service graph is {1}".format(
                    service_graph, contract, contract_service_graph_ref))

    if state == "query":

        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            ops.append(dict("remove", path=contract_service_graph_path))

    elif state == "present":

        service_nodes_relationship = []
        contract_service_nodes = template_contract_service_graph.get("serviceNodesRelationship")
        # Validation to check if amount of service graph nodes provided is matching the contract service graph.
        if len(contract_service_nodes) != len(service_nodes):
            mso.fail_json(msg="Number of service graph nodes provided is inconsistent with current service graph")
        if template_contract_service_graph.get("serviceGraphRef") != service_graph_ref:
            mso.fail_json(msg="Sevice graph '{0}' is not attached to contract {1}. Existing service graph is {2}".format(service_graph, contract, mso.existing.get("serviceGraphRef")))
        for node_id, service_node in enumerate(contract_service_nodes):
            contract_service_node = mso.dict_from_ref(service_node.get("serviceNodeRef"))
            node_content = {
                'serviceNodeRef': contract_service_node,
            }
            if site_type == "on-premise":
                node_content['providerConnector'] = {
                    'clusterInterface': {
                    'dn': service_nodes[node_id].get("provider_cluster_interface")
                    },
                    'subnets': []
                }
                node_content['consumerConnector'] = {
                    'clusterInterface': {
                    'dn': service_nodes[node_id].get("consumer_cluster_interface")
                    },
                    'subnets': []
            }
                if service_nodes[node_id].get("provider_redirect_policy"):
                    node_content['providerConnector']['redirectPolicy'] = {
                        'dn' : service_nodes[node_id].get("provider_redirect_policy")
                    }
                if service_nodes[node_id].get("consumer_redirect_policy"):
                    node_content['consumerConnector']['redirectPolicy'] = {
                        'dn': service_nodes[node_id].get("consumer_redirect_policy")
                    }
            else:
                if service_nodes[node_id].get("index"):
                    node_content['deviceConfiguration'] = {
                        'cloudDevInst': service_nodes[node_id].get("index")
                    }
                if service_nodes[node_id].get("listeners"):
                    listeners = service_nodes[node_id].get("listeners")
                    listener_list = []
                    for listener in listeners:
                        listener_payload = {}
                        listener_payload['name'] = listener.get('name')
                        listener_payload['port'] = listener.get('port')
                        listener_payload['protocol'] = listener.get('protocol')
                        rules = listener.get('rules')
                        rule_list = []
                        for rule_idx, rule in enumerate(rules):
                            rule_payload = {}
                            rule_payload['name'] = rule.get('name')
                            rule_payload['actionType'] = rule.get('action_type')
                            rule_payload['protocol'] = rule.get('protocol')
                            rule_payload['port'] = rule.get('port')
                            rule_payload['index'] = rule_idx
                            rule_list.append(rule_payload)
                        listener_payload['rules'] = rule_list
                        listener_payload['certificates'] = []
                        listener_list.append(listener_payload)
                    node_content['deviceConfiguration'] = {
                        'cloudLoadBalancer': {
                            'listeners': listener_list
                        }
                    }
            service_nodes_relationship.append(node_content)
        service_graph_payload = dict(
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=service_graph_template,
                schemaId=service_graph_schema_id
            ),
            serviceNodesRelationship=service_nodes_relationship
        )

        if mso.existing:
            payload = service_graph_payload
            # ops.append(dict(op='replace', path=contract_service_graph_path, value=service_graph_payload))
        else:
            if payload.get('contractRef'):
                contract_service_graph_path = '/sites/{0}/contracts/-'.format(site_template)
                payload['serviceGraphRelationship'] = service_graph_payload
            else:
                payload = service_graph_payload
            # ops.append(dict(op='add', path=contract_service_graph_path, value=payload))

    mso.sanitize(payload, collate=True)

    if not mso.existing:
        ops.append(dict(op='add', path=contract_service_graph_path, value=payload))
    else:
        ops.append(dict(op='replace', path=contract_service_graph_path, value=payload))

    mso.existing = mso.proposed
    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()


