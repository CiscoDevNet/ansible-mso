#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_physical_domain
short_description: Manage Physical Domains on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Physical Domains on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  physical_domain:
    description:
    - The name of the Physical Domain.
    type: str
    aliases: [ name ]
  physical_domain_uuid:
    description:
    - The uuid of the Physical Domain.
    - This parameter is required when the O(physical_domain) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the Physical Domain.
    type: str
  pool:
    description:
    - The name of the VLAN Pool.
    - Providing an empty string will remove the pool from the Physical Domain.
    type: str
    aliases: [ vlan_pool ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new physical domain
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    physical_domain: ansible_test_physical_domain
    pool: ansible_test_vlan_pool
    state: present
  register: create

- name: Query a physical domain with name
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    physical_domain: ansible_test_physical_domain
    state: query
  register: query_one

- name: Query a physical domain with UUID
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    physical_domain_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_with_uuid

- name: Query all physical domains in the template
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a vlan pool from a physical domain
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    physical_domain: ansible_test_physical_domain
    pool: ""
    state: present

- name: Delete a physical domain
  cisco.mso.ndo_physical_domain:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    physical_domain: ansible_test_physical_domain
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        physical_domain=dict(type="str", aliases=["name"]),
        physical_domain_uuid=dict(type="str", aliases=["uuid"]),
        description=dict(type="str"),
        pool=dict(type="str", aliases=["vlan_pool"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["physical_domain"]],
            ["state", "present", ["physical_domain"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    physical_domain = module.params.get("physical_domain")
    physical_domain_uuid = module.params.get("physical_domain_uuid")
    pool = module.params.get("pool")
    description = module.params.get("description")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/domains"
    match = get_physical_domain(mso_template, physical_domain_uuid, physical_domain)

    if physical_domain_uuid or physical_domain:
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = match  # Query all objects

    if state == "present":
        mso.existing = {}

        if match:
            if physical_domain and match.details.get("name") != physical_domain:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=physical_domain))
                match.details["name"] = physical_domain

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if pool and match.details.get("pool") != pool:
                ops.append(dict(op="replace", path="{0}/{1}/pool".format(path, match.index), value=mso_template.get_vlan_pool_uuid(pool)))
                match.details["pool"] = pool
            elif pool == "" and match.details.get("pool"):
                ops.append(dict(op="remove", path="{0}/{1}/pool".format(path, match.index)))
                match.details.pop("pool")

            mso.sanitize(match.details)

        else:
            payload = {"name": physical_domain, "templateId": mso_template.template.get("templateId"), "schemaId": mso_template.template.get("schemaId")}
            if description:
                payload["description"] = description
            if pool:
                payload["pool"] = mso_template.get_vlan_pool_uuid(pool)

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            if pool:
                payload["pool"] = pool

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_physical_domain(mso_template, physical_domain_uuid, physical_domain)
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_physical_domain(mso_template, uuid=None, name=None, fail_module=False):
    """
    Get the Physical Domain by UUID or Name.
    :param uuid: UUID of the Physical Domain to search for -> Str
    :param name: Name of the Physical Domain to search for -> Str
    :param fail_module: When match is not found fail the ansible module -> Bool
    :return: Dict | None | List[Dict] | List[]: The processed result which could be:
              When the UUID | Name is existing in the search list -> Dict
              When the UUID | Name is not existing in the search list -> None
              When both UUID and Name are None, and the search list is not empty -> List[Dict]
              When both UUID and Name are None, and the search list is empty -> List[]
    """
    match = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("domains", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs("Physical Domain", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
    return match  # Query all objects


if __name__ == "__main__":
    main()
