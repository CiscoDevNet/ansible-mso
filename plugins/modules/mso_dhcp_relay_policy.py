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
module: mso_dhcp_relay_policy
short_description: Configure a DHCP Relay policy.
description:
- Configure a DHCP Relay policy.
author:
- Jorge Gomez (@jorgegome2307)
options:
  name:
    description:
    - Name of the DHCP Relay Policy
    type: str
  description:
    description:
    - Description of the DHCP Relay Policy
    type: str
  tenant:
    description:
    - Tenant where the DHCP Relay Policy is located.
    type: str
  state:
    description:
    - State of the DHCP Relay Policy
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
        name=dict(type="str"),
        description=dict(type="str"),
        tenant=dict(type="str"),
        state=dict(
            type="str", default="present", choices=["absent", "present", "query"]
        ),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    tenant = module.params.get("tenant")
    state = module.params.get("state")

    mso = MSOModule(module)

    path = "policies/dhcp/relay"

    if name:
        mso.existing = mso.get_obj(path, name=name, key="DhcpRelayPolicies")
        if mso.existing:
            policy_id = mso.existing.get("id")
            path = path + "/" + policy_id
    else:
        # For Querying purposes. Not supported
        mso.existing = mso.query_objs(path, key="DhcpRelayPolicies")

    mso.previous = mso.existing

    tenant_id = mso.lookup_tenant(tenant)
    payload = dict(
        name=name,
        desc=description,
        policyType="dhcp",
        policySubtype="relay",
        tenantId=tenant_id,
    )

    response = {}
    changed = False

    if state == "query":
        pass

    elif state == "absent":
        if mso.existing:
            mso.existing = mso.request(path, method="DELETE", data=mso.sent)
            changed = True

    elif state == "present":

        mso.sanitize(payload, collate=True)

        if mso.existing:
            if mso.check_changed():
                mso.existing = mso.request(path, method="PUT", data=mso.sent)
                changed = True
                response["name"] = mso.existing["name"]
                response["tenant"] = mso.existing["tenantId"]
        else:
            mso.existing = mso.request(path, method="POST", data=mso.sent)
            changed = True
            response["name"] = payload["name"]
            response["tenant"] = payload["tenantId"]

    mso.exit_json(changed=changed, meta=response)


if __name__ == "__main__":
    main()
