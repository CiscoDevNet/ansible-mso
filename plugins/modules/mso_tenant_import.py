#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_tenant_import
short_description: Manage tenants
description:
- Manage tenants on Cisco ACI Multi-Site.
author:
- Sabari Jaganathan (@sajagana)
options:
  tenant_name:
    description:
    - The name of the tenant.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name of the tenant to be displayed in the web UI.
    type: str
  description:
    description:
    - The description for this tenant.
    type: str
  sites:
    description:
    - A list of associated sites for this tenant.
    - Using this property will replace any existing associated sites.
    type: list
    elements: str
  msc_only:
    description:
    - MSC Only C(false) is used to delete the imported tenant from the MSO and Sites.
    - C(true) is used to remove the tenant only from the MSO.
    type: bool
    choices: [ true, false ]
    default: true
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Import the existing tenant from Sites to MSO
  cisco.mso.mso_tenant_import:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant_name: north_europe
    display_name: North European Datacenter
    description: This tenant manages the NEDC environment.
    state: present
  delegate_to: localhost

- name: Remove a tenant only from MSO
  cisco.mso.mso_tenant_import:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant_name: north_europe
    msc_only: true
    state: absent
  delegate_to: localhost

- name: Remove a tenant from MSO and Sites
  cisco.mso.mso_tenant_import:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant_name: north_europe
    msc_only: false
    state: absent
  delegate_to: localhost

- name: Query an imported tenant with name
  cisco.mso.mso_tenant_import:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant_name: north_europe
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all tenants
  cisco.mso.mso_tenant_import:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        tenant_name=dict(type="str", aliases=["name"]),
        display_name=dict(type="str"),
        description=dict(type="str"),
        sites=dict(type="list", elements="str"),
        msc_only=dict(type="bool", default=True, choices=[True, False]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant_name"]],
            ["state", "present", ["tenant_name", "sites", "display_name"]],
        ],
    )

    tenant_name = module.params.get("tenant_name")
    display_name = module.params.get("display_name")
    description = module.params.get("description")
    sites = module.params.get("sites")
    msc_only = module.params.get("msc_only")
    state = module.params.get("state")

    mso = MSOModule(module)
    # Mapping sites with site ids
    if sites:
        site_ids_map = mso.lookup_sites(sites)

    path = "tenants"

    # Query for existing object(s)
    if tenant_name:
        mso.existing = mso.get_obj(path, name=tenant_name)
        if mso.existing:
            tenant_id = mso.existing.get("id")
            # If we found an existing object, continue with it
            path = "{0}/{1}".format(path, tenant_id)
    else:
        mso.existing = mso.query_objs(path)

    if state == "query":
        pass
    elif state == "absent":
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                if msc_only:
                    path = "{0}?msc-only=true".format(path)
                mso.existing = mso.request(path, method="DELETE")

    elif state == "present":
        mso.previous = mso.existing
        payload = dict(
            name=tenant_name,
            displayName=display_name,
            description=description,
            siteAssociations=site_ids_map,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            if mso.check_changed():
                if module.check_mode:
                    mso.existing = mso.proposed
                else:
                    mso.existing = mso.request(path, method="PUT", data=mso.sent)
        else:
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method="POST", data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
