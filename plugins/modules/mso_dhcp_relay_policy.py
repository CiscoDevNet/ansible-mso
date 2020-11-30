#!/usr/bin/python
# Copyright: (c) 2020, Jorge Gomez Velasquez <jgomezve@cisco.com>

ANSIBLE_METADATA = {"metadata_version": "0.1", "status": ["preview"]}

DOCUMENTATION = r"""
---
module: mso_dhcp_relay_policy
short_description: Configure a DHCP Relay policy.
description:
- Configure a DHCP Relay policy.
version_added: '2.10'
options:
  name:
    description:
    - Name of the DHCP Relay Policy
    type: str
    required: yes
  description:
    description:
    - Description of the DHCP Relay Policy
    type: str
    required: yes
  tenant:
    description:
    - Tenant where the DHCP Relay Policy is located.
    type: str
    required: yes
  state:
    description:
    - State of the DHCP Relay Policy
    type: str
    required: yes
author:
- Jorge Gomez Velasquez
"""

EXAMPLES = r"""

"""

RETURN = r"""

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec

def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        name=dict(type='str'),
        description=dict(type='str'),
        tenant=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,

    )

    name = module.params.get('name')
    description = module.params.get('description')
    tenant = module.params.get('tenant')
    state = module.params.get('state')

    mso = MSOModule(module)

    path = 'policies/dhcp/relay'

    if name:
        mso.existing = mso.get_obj(path, name=name, key='DhcpRelayPolicies')
        if mso.existing:
            policy_id = mso.existing.get('id')
            path = path + "/" + policy_id
    else:
        # For Querying purposes. Not supported
        mso.existing = mso.query_objs(path, key='DhcpRelayPolicies')

    mso.previous = mso.existing

    tenant_id = mso.lookup_tenant(tenant)
    payload = dict(
        name=name,
        desc=description,
        policyType="dhcp",
        policySubtype="relay",
        tenantId=tenant_id
    )

    response = {}
    changed = False

    if state == 'absent':
        if mso.existing:
            mso.existing = mso.request(path, method='DELETE', data=mso.sent)
            changed = True
    elif state == 'present':

        mso.sanitize(payload, collate=True)

        if mso.existing:
            if mso.check_changed():
                mso.existing = mso.request(path, method='PUT', data=mso.sent)
                changed = True
                response['name'] = mso.existing['name']
                response['tenant'] = mso.existing['tenantId']
        else:
            mso.existing = mso.request(path, method='POST', data=mso.sent)
            changed = True
            response['name'] = payload['name']
            response['tenant'] = payload['tenantId']

    mso.exit_json(changed=changed, meta=response)


if __name__ == "__main__":
    main()