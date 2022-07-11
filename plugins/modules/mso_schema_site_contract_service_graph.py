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
      name:
        description:
        - The name of the service graph node.
        required: true
        type: str
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

