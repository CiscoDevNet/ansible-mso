#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_schema_template_deploy
short_description: Deploy templates to sites for NDO v3.7 and higher
description:
- Deploy templates to sites.
- Prior to deploy or redeploy a schema validation is executed.
- When schema validation fails, M(cisco.mso.ndo_schema_template_deploy) fails and deploy or redeploy will not be executed.
- Only supports NDO v3.7 and higher
author:
- Akini Ross (@akinross)
- Samita Bhattacharjee (@samiib)
options:
  schema:
    description:
    - The name of the schema.
    type: str
  schema_id:
    description:
    - The ID of the schema.
    type: str
  template:
    description:
    - The name of the template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - This parameter or O(template) is required.
    type: str
  template_type:
    description:
    - The type of the template.
    - O(template_type) is ignored when O(template_id) is provided.
    type: str
    aliases: [ type ]
    default: application
    choices: [ tenant, l3out, application, fabric_policy, fabric_resource, monitoring_tenant, monitoring_access, service_device ]
  sites:
    description:
    - The list of site names where the template will be undeployed.
    - When O(sites) is not provided the template will be undeployed from all sites.
    type: list
    elements: str
  state:
    description:
    - Use C(deploy) to deploy a template.
    - Use C(redeploy) to redeploy a template.
    - Use C(undeploy) to undeploy a template from sites.
    - Use C(query) to get deployment status.
    type: str
    choices: [ deploy, redeploy, undeploy, query ]
    default: deploy
seealso:
- module: cisco.mso.mso_schema_site
- module: cisco.mso.mso_schema_template
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Deploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: deploy

- name: Deploy a fabric policy template
  cisco.mso.ndo_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: Fabric Policy 1
    type: fabric_policy
    state: deploy

- name: Redeploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: redeploy

- name: Redeploy a fabric policy template using template id
  cisco.mso.ndo_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: '{{ fabric_policy_1.current.templateId }}'
    state: deploy

- name: Undeploy a schema template
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    sites: [Site1, Site2]
    state: undeploy

- name: Undeploy a fabric policy template from all sites
  cisco.mso.ndo_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: Fabric Policy 1
    type: fabric_policy
    state: undeploy

- name: Undeploy a fabric policy template from one site
  cisco.mso.ndo_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: Fabric Policy 1
    type: fabric_policy
    sites: [Site1]
    state: undeploy

- name: Query a schema template deploy status
  cisco.mso.ndo_schema_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result

- name: Query a fabric policy template deploy status
  cisco.mso.ndo_template_deploy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: Fabric Policy 1
    type: fabric_policy
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import TEMPLATE_TYPES


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str"),
        schema_id=dict(type="str"),
        template=dict(type="str"),
        template_id=dict(type="str"),
        template_type=dict(type="str", choices=list(TEMPLATE_TYPES), default="application", aliases=["type"]),
        sites=dict(type="list", elements="str"),
        state=dict(
            type="str",
            default="deploy",
            choices=["deploy", "redeploy", "undeploy", "query"],
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("schema", "schema_id"),
        ],
        required_one_of=[["template", "template_id"]],
    )

    schema = module.params.get("schema")
    schema_id = module.params.get("schema_id")
    template = module.params.get("template")
    template_id = module.params.get("template_id")
    template_type = module.params.get("template_type")
    sites = module.params.get("sites")
    state = module.params.get("state")

    mso = MSOModule(module)

    if template_id is not None:
        template_type = None
    elif template_type == "application":
        template = template.replace(" ", "")

    mso_template = MSOTemplate(mso, template_type, template, template_id, schema, schema_id)

    if template is None:
        template = mso_template.template_name
    if template_id is None:
        template_id = mso_template.template_id
    if template_type is None:
        template_type = mso_template.template_type
    else:
        template_type = TEMPLATE_TYPES[template_type]["template_type"]

    mso_template.validate_template(template_type)

    is_application = template_type == "application"
    if is_application:
        if schema_id is None and schema is None:
            schema_id = mso_template.schema_id
        elif schema is not None and schema_id is None:
            schema_id = mso.lookup_schema(schema)

    path = None
    if state == "query":
        if is_application:
            path = "status/schema/{0}/template/{1}".format(schema_id, template)
        elif mso_template.deploy_task_id:
            path = "task/{0}".format(mso_template.deploy_task_id)
        method = "GET"
        payload = None
    else:
        path = "task"
        method = "POST"
        if is_application:
            payload = dict(schemaId=schema_id, templateName=template)
        else:
            payload = dict(templateId=template_id)
        if state == "deploy":
            payload.update(isRedeploy=False)
        elif state == "redeploy":
            payload.update(isRedeploy=True)
        elif state == "undeploy":
            payload.update(undeploy=get_site_ids(mso, mso_template, sites))
        if is_application and state != "undeploy":
            mso.validate_schema(schema_id)
    if not module.check_mode:
        mso.existing = mso.request(path, method=method, data=payload) if path else {}
    mso.exit_json()


def get_site_ids(mso, mso_template, sites):
    if sites:
        return [site.get("siteId") for site in mso.lookup_sites(sites)]
    return mso_template.deployed_site_ids


if __name__ == "__main__":
    main()
