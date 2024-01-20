#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template
short_description: Manage templates in schemas
description:
- Manage templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  tenant:
    description:
    - The tenant used for this template.
    type: str
    required: true
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  schema_description:
    description:
    - The description of Schema is supported on versions of MSO that are 3.3 or greater.
    type: str
  template_description:
    description:
    - The description of template is supported on versions of MSO that are 3.3 or greater.
    type: str
  template:
    description:
    - The name of the template.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
 template_type:
    description:
     - Deployment Mode. Use stretched-template for Multi-Site or non-stretched-template for Autonomous
     type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- Due to restrictions of the MSO REST API this module creates schemas when needed, and removes them when the last template has been removed.
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_site
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new template to a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: present
  delegate_to: localhost

- name: Remove a template from a schema
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: absent
  delegate_to: localhost

- name: Query a template
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    template: Template 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all templates
  cisco.mso.mso_schema_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: Tenant 1
    schema: Schema 1
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, diff_dicts, update_payload, mso_reference_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dhcp_relay_policy_name=dict(type="str", required=True),
        template=dict(type="str", required=True),
        description=dict(type="str"),
        epg=dict(type="dict"),
        anp=dict(type="str"),
        external_epg=dict(type="dict"),
        ip=dict(type="str", required=True),
        use_server_vrf=dict(type="bool", default=False),
        state = dict(type="str", default="present", choices=["absent", "present", "query"])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["template"]],
            ["state", "present", ["template"]],
        ],
    )

    template = module.params.get("template")
    if template is not None:
        template = template.replace(" ", "")
    dhcp_relay_policy_name =  module.params.get("dhcp_relay_policy_name")
    state = module.params.get("state")
    anp = module.params.get("anp")
    description = module.params.get("description")
    use_server_vrf = module.params.get("use_server_vrf")
    epg = module.params.get("epg")
    if epg is not None and epg.get("template") is not None:
        epg["template"] = epg.get("template").replace(" ", "")
    external_epg = module.params.get("external_epg")
    if external_epg is not None and external_epg.get("external_epg") is not None:
        external_epg["external_epg"] = external_epg.get("external_epg").replace(" ", "")
    ip = module.params.get("ip")


    mso = MSOModule(module)
    
    template_type = "tenantPolicy"


    templates = mso.request(path="templates/summaries", method="GET", api_version="v1")


    mso.existing = {}

    template_id = ''
    if templates:
        for temp in templates:
            if temp['templateName'] == template and temp['templateType'] == template_type:
                template_id = temp['templateId']

    if not template_id:
        mso.fail_json(msg="Template '{template}' not found".format(template=template))


    mso.existing = mso.request(path=f"templates/{template_id}", method="GET", api_version="v1")

    # try to find if the dhcp relay policy exist
    dhcp_pol_exist = False
    if 'template' in mso.existing['tenantPolicyTemplate'] and 'dhcpRelayPolicies' in mso.existing['tenantPolicyTemplate']['template']:
        for count, r in enumerate(mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies']):
            if r['name'] == dhcp_relay_policy_name:
                dhcp_pol_index = count
                dhcp_pol_exist = True

    ##try to find if the relay exist
    relay_exist = False


    if epg:
        epg_schema_id, epg_schema_path, epg_schema_obj = mso.query_schema(epg['schema'])

        # Get template
        epg_templates = [t.get("name") for t in epg_schema_obj.get("templates")]
        if epg['template'] not in epg_templates:
            mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(epg['template'], ", ".join(epg_templates)))
        epg_template_idx = epg_templates.index(epg['template'])

        anps = [a.get("name") for a in epg_schema_obj.get("templates")[epg_template_idx]["anps"]]
        if epg['anp'] not in anps:
            mso.fail_json(msg="Provided anp '{0}' does not exist. Existing anps: {1}".format(epg['anp'], ", ".join(anps)))
        anp_idx = anps.index(epg['anp'])

        # Get EPG
        epgs = [e.get("name") for e in epg_schema_obj.get("templates")[epg_template_idx]["anps"][anp_idx]["epgs"]]
        if epg['name'] not in epgs:
            mso.fail_json(msg="Provided epg '{epg}' does not exist. Existing epgs: {epgs}".format(epg=epg['name'], epgs=", ".join(epgs)))
        epg_idx = epgs.index(epg['name'])

        epg_uuid = epg_schema_obj.get("templates")[epg_template_idx]["anps"][anp_idx]["epgs"][epg_idx]['uuid']

        if dhcp_pol_exist:
            for count, r in enumerate(mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers']):
                if 'epgRef' in r and r['epgRef'] == epg_uuid and r['ip'] == ip:
                    relay_index = count
                    relay_exist = True

    elif external_epg:
        ext_epg_schema_id, ext_epg_schema_path, ext_epg_schema_obj = mso.query_schema(external_epg['schema'])

        # Get template
        ext_epg_templates = [t.get("name") for t in ext_epg_schema_obj.get("templates")]
        if external_epg['template'] not in ext_epg_templates:
            mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(external_epg['template'], ", ".join(ext_epg_templates)))
        ext_epg_template_idx = ext_epg_templates.index(external_epg['template'])

        # Get external EPGs
        external_epgs = [e.get("name") for e in ext_epg_schema_obj.get("templates")[ext_epg_template_idx]["externalEpgs"]]
        if external_epg['name'] not in external_epgs:
            mso.fail_json(msg="Provided External EPG '{0}' does not exist.".format(external_epg['name']))
        external_epg_idx = external_epgs.index(external_epg['name'])
        external_epg_uuid = ext_epg_schema_obj.get("templates")[ext_epg_template_idx]["externalEpgs"][external_epg_idx]['uuid']

        if dhcp_pol_exist:
            for count, r in enumerate(mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers']):
                if 'externalEpgRef' in r and r['externalEpgRef'] == external_epg_uuid and r['ip'] == ip:
                    relay_index = count
                    relay_exist = True

    else:
        mso.fail_json(msg="Both EPG and External EPG cannot be empty".format(template=template))
        
    




    if state == "query":
        if not mso.existing:
            if template:
                mso.fail_json(msg="Template '{0}' not found".format(template))
            else:
                mso.existing = []
        mso.exit_json()

    template_path = f"templates/{template_id}"

    mso.previous = mso.existing
    if state == "absent":
        mso.proposed = mso.sent = {}
        if relay_exist:
            del mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers'][relay_index]
            if len(mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers']) == 0:
                del mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]
            if len(mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies']) == 0:
                del mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies']
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = {}

    elif state == "present":

        new_dhcp_relay_policy = {
            "name": dhcp_relay_policy_name,
            "description": "",
            "providers" : []
        }
        if description:
            new_dhcp_relay_policy['description'] = description
        new_provider = {
            "ip": ip,
            "useServerVrf": use_server_vrf
        }
        if epg:
            new_provider['epgRef'] = epg_uuid
        else:
            new_provider['externalEpgRef'] = external_epg_uuid

        #dhcp_pol_exist doesn't exitst, need be created
        if not dhcp_pol_exist:

            if not 'dhcpRelayPolicies' in mso.existing['tenantPolicyTemplate']['template']:
                mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'] = []
            
            new_dhcp_relay_policy['providers'].append(new_provider)
            mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'].append(new_dhcp_relay_policy)

            # mso.sanitize(payload, collate=True)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed
        
        elif not relay_exist:
            ####check if description need be updated
            if description and mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['description'] != description:
                mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['description'] = description
            mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers'].append(new_provider)
            if not module.check_mode:
                mso.request(template_path, method="PUT", data=mso.existing)
            mso.existing = mso.proposed

        else:
            update_description = False
            ####check if description need be updated
            if description and mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['description'] != description:
                mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['description'] = description
                update_description = True
            #entry exist, check if need be udpated
            current = mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers'][relay_index].copy()
            diff = diff_dicts(new_provider,current)

            if diff or update_description:
                mso.existing['tenantPolicyTemplate']['template']['dhcpRelayPolicies'][dhcp_pol_index]['providers'][relay_index] = update_payload(diff=diff, payload=current)
                if not module.check_mode:
                    mso.request(template_path, method="PUT", data=mso.existing)
                mso.existing = mso.proposed

    mso.exit_json()


if __name__ == "__main__":
    main()
