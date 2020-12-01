#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Jorge Gomez Velasquez <jgomezve@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: mso_dhcp_relay_policy_provider
short_description: Configure DHCP providers in a DHCP Relay policy.
description:
- Configure DHCP providers in a DHCP Relay policy.
author:
- Jorge Gomez (@jorgegome2307)
options:
  name:
    description:
    - Name of the DHCP Relay Policy
    type: str
    required: yes
  ip:
    description:
    - IP address of the DHCP Server
    type: str
    required: yes
  tenant:
    description:
    - Tenant where the DHCP provider is located.
    type: str
    required: yes
  schema:
    description:
    - Schema where the DHCP provider is configured
    type: str
    required: yes
  template:
    description:
    - template where the DHCP provider is configured
    type: str
    required: yes
  application_profile:
    description:
    - Application Profile where the DHCP provider is configured
    type: str
  endpoint_group:
    description:
    - EPG where the DHCP provider is configured
    type: str
  external_endpoint_group:
    description:
    - External EPG where the DHCP provider is configured
    type: str
  state:
    description:
    - State of the DHCP Relay provider
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""

"""

RETURN = r"""

"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True),
        ip=dict(type="str", required=True),
        tenant=dict(type="str", required=True),
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        application_profile=dict(type="str"),
        endpoint_group=dict(type="str"),
        external_endpoint_group=dict(type="str"),
        state=dict(
            type="str", default="present", choices=["absent", "present", "query"]
        ),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        # required_if=[
        #     ["state", "absent", ["external_endpoint_group"]],
        #     ["state", "absent", ["endpoint_group"]],
        # ],  TODO: Required_if with 'OR'
    )

    name = module.params.get("name")
    ip = module.params.get("ip")
    tenant = module.params.get("tenant")
    schema = module.params.get("schema")
    template = module.params.get("template")
    application_profile = module.params.get("application_profile")
    endpoint_group = module.params.get("endpoint_group")
    external_endpoint_group = module.params.get("external_endpoint_group")
    state = module.params.get("state")

    mso = MSOModule(module)

    path = "policies/dhcp/relay"

    if name:
        mso.existing = mso.get_obj(path, name=name, key="DhcpRelayPolicies")
        if mso.existing:
            policy_id = mso.existing.get("id")
            path = path + "/" + policy_id
        else:
            mso.fail_json(
                msg="Error DHCP Policy Relay {name} does not exist".format(name=name)
            )
    else:
        mso.existing = mso.query_objs(path, key="DhcpRelayPolicies")

    payload = mso.existing
    tenant_id = mso.lookup_tenant(tenant)
    schema_id = mso.lookup_schema(schema)
    ext_epg_type = True

    if endpoint_group is not None:
        epgRef = (
            "/schemas/{schemaId}/templates/{templateName}/anps/{app}/epgs/{epg}".format(
                schemaId=schema_id,
                templateName=template,
                app=application_profile,
                epg=endpoint_group,
            )
        )
        provider = dict(
            addr=ip, epgRef=epgRef, externalEpgRef="", l3Ref="", tenantId=tenant_id
        )
        ext_epg_type = False
    elif external_endpoint_group is not None:
        externalEpgRef = "/schemas/{schemaId}/templates/{templateName}/externalEpgs/{ext_epg}".format(
            schemaId=schema_id, templateName=template, ext_epg=external_endpoint_group
        )
        provider = dict(
            addr=ip,
            externalEpgRef=externalEpgRef,
            epgRef="",
            l3Ref="",
            tenantId=tenant_id,
        )
    else:
        mso.fail_json(msg="Invalid provider type")

    if "provider" in payload:
        providers = payload["provider"]
    else:
        providers = []

    if state == "query":
        pass  # TODO: Not supported ??  MSO  Model does not allow to query a provider but the whole DHCP Policy

    elif state == "absent":
        mso.previous = mso.existing
        changed_object = False

        if mso.existing:
            payload = mso.existing
            if check_new_provider(providers, provider, ext_epg_type):
                providers.remove(provider)
                changed_object = True

    elif state == "present":

        mso.previous = mso.existing
        changed_object = False

        if not check_new_provider(providers, provider, ext_epg_type):
            providers.append(provider)
            changed_object = True

    payload["provider"] = providers
    response = {}
    changed = False

    mso.sanitize(payload, collate=True)

    if (
        mso.check_changed() or changed_object
    ):  # mso.previous != mso.existing (Check why it does not work)
        mso.existing = mso.request(path, method="PUT", data=mso.sent)
        changed = True
        response["msg"] = "Provider modified"
        response["tenant"] = mso.existing["provider"]
    elif not changed_object:
        response["msg"] = "Provider already exists / Provider does not exits"

    mso.exit_json(changed=changed, meta=response)


def check_new_provider(provider_list, provider_to_add, ext_epg_type):
    found = False
    for provider in provider_list:
        if not ext_epg_type:
            if (
                provider["addr"] == provider_to_add["addr"]
                and provider["epgRef"] == provider_to_add["epgRef"]
                and provider["tenantId"] == provider_to_add["tenantId"]
            ):
                found = True
        else:
            if (
                provider["addr"] == provider_to_add["addr"]
                and provider["externalEpgRef"] == provider_to_add["externalEpgRef"]
                and provider["tenantId"] == provider_to_add["tenantId"]
            ):
                found = True
    return found


if __name__ == "__main__":
    main()
