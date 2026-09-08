#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2023, Anvitha Jain (@anvjain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_tenant
short_description: Manage tenants
description:
- Manage tenants on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name of the tenant to be displayed in the web UI.
    - On Nexus Dashboard (ND) 4.2+ / NDO 5.2+, O(display_name) must equal O(tenant); the API
      rejects O(sites) association updates otherwise. When omitted on creation, it defaults to
      O(tenant). Once set, the previous value is retained and resent on every update, so ensure
      O(display_name) still matches O(tenant) before any update that changes O(sites).
    type: str
  description:
    description:
    - The description for this tenant.
    type: str
  users:
    description:
    - A list of associated users for this tenant.
    - Using this property will replace any existing associated users.
    - Admin user is always added to the associated user list irrespective of this parameter being used, except on
      Nexus Dashboard (ND) 4.2+ / NDO 5.2+ (see the deprecation note below).
    - On ND 4.2+ / NDO 5.2+, user associations are derived from tenant-domain membership and the platform
      automatically and immutably associates certain users (for example, superusers in the built-in
      all-tenants-domain) with every tenant. This parameter is deprecated on ND 4.2+ / NDO 5.2+, is no longer
      able to reliably manage user associations, and may be removed in a future version.
    type: list
    elements: str
  remote_users:
    description:
    - A list of associated remote users for this tenant.
    - This parameter is deprecated on Nexus Dashboard (ND) 4.2+ / NDO 5.2+ for the same reasons as O(users).
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the associated remote user for this tenant.
        required: true
        type: str
      login_domain:
        description:
        - Domain name of the associated remote user for this tenant.
        required: true
        type: str
  sites:
    description:
    - A list of associated sites for this tenant.
    - Using this property will replace any existing associated sites.
    type: list
    elements: str
  orchestrator_only:
    description:
    - Orchestrator Only C(no) is used to delete the tenant from the MSO and Sites/APIC.
    - C(yes) is used to remove the tenant only from the MSO.
    type: str
    choices: [ 'yes', 'no' ]
    default: 'yes'
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
- name: Add a new tenant
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    display_name: North European Datacenter
    description: This tenant manages the NEDC environment.
    state: present

- name: Remove a tenant from MSO and Site/APIC
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    orchestrator_only: 'no'
    state: absent

- name: Remove a tenant from MSO only
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    orchestrator_only: 'yes'
    state: absent

- name: Query a tenant
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: north_europe
    state: query
  register: query_result

- name: Query all tenants
  cisco.mso.mso_tenant:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, ndo_remote_user_spec, is_platform_version_at_least
from ansible_collections.cisco.mso.plugins.module_utils.constants import YES_OR_NO_TO_BOOL_STRING_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        description=dict(type="str"),
        display_name=dict(type="str"),
        tenant=dict(type="str", aliases=["name"]),
        users=dict(type="list", elements="str"),
        remote_users=dict(type="list", elements="dict", options=ndo_remote_user_spec()),
        sites=dict(type="list", elements="str"),
        orchestrator_only=dict(type="str", default="yes", choices=["yes", "no"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant"]],
            ["state", "present", ["tenant"]],
        ],
    )

    description = module.params.get("description")
    display_name = module.params.get("display_name")
    tenant = module.params.get("tenant")
    orchestrator_only = module.params.get("orchestrator_only")
    state = module.params.get("state")
    remote_users = module.params.get("remote_users")
    users = module.params.get("users")

    mso = MSOModule(module)

    tenant_id = None
    path = "tenants"

    # Query for existing object(s)
    if tenant:
        mso.existing = mso.get_obj(path, name=tenant)
        if mso.existing:
            tenant_id = mso.existing.get("id")
            # If we found an existing object, continue with it
            path = "tenants/{id}".format(id=tenant_id)
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
                path = "{0}?msc-only={1}".format(path, YES_OR_NO_TO_BOOL_STRING_MAP.get(orchestrator_only))
                mso.existing = mso.request(path, method="DELETE")

    elif state == "present":
        mso.previous = mso.existing

        # On ND 4.2+ / NDO 5.2+, userAssociations are derived from tenant-domain membership: the
        # platform auto-backfills it (e.g. immutable all-tenants-domain members) regardless of
        # what is sent, so submitting a computed list unconditionally would cause perpetual
        # "changed" drift when users/remote_users are not actually used. Only manage/send
        # userAssociations on these versions when the caller explicitly opted in via users
        # and/or remote_users; otherwise leave the key out of the payload entirely so the API
        # continues to own it. Older versions keep the previous behavior (always managed).
        users_specified = users is not None or remote_users is not None
        is_ndo_5_2_or_later = is_platform_version_at_least(mso.get_platform_version().get("version"), "5.2")
        if is_ndo_5_2_or_later and users_specified:
            module.deprecate(
                msg="The 'users' and 'remote_users' parameters are deprecated on Nexus Dashboard (ND) 4.2+ / NDO 5.2+. "
                "User associations are derived from tenant-domain membership and are no longer reliably managed via this module.",
                version="4.0.0",
                collection_name="cisco.mso",
            )

        # Convert sites and users
        sites = mso.lookup_sites(module.params.get("sites"))
        users = mso.lookup_users(users)
        if remote_users is not None:
            users += mso.lookup_remote_users(remote_users)

        payload = dict(
            description=description,
            id=tenant_id,
            name=tenant,
            displayName=display_name,
            siteAssociations=sites,
        )
        if not is_ndo_5_2_or_later or users_specified:
            payload["userAssociations"] = users

        mso.sanitize(payload, collate=True)

        # Ensure displayName is not undefined
        if mso.sent.get("displayName") is None:
            mso.sent["displayName"] = tenant

        if mso.existing:
            # On ND 4.2+, the platform returns extra cloud-account keys (awsAccount, azureAccount,
            # gcpAccount, gatewayRouter) on each siteAssociations entry that this module never
            # manages/sends (lookup_sites() only builds siteId/securityDomains). Left as-is, the
            # exact-match list-of-dicts comparison in check_changed()/issubset() would report a
            # perpetual false-positive "changed" for any tenant with a site association, so these
            # nested keys are excluded from the comparison (the rest of each siteAssociations
            # entry, e.g. siteId/securityDomains, is still compared).
            ignore_keys = [
                "siteAssociations.awsAccount",
                "siteAssociations.azureAccount",
                "siteAssociations.gcpAccount",
                "siteAssociations.gatewayRouter",
            ]

            # On ND 4.2+ / NDO 5.2+, userAssociations may be sent (when users/remote_users are
            # explicitly used) but its true state can be further adjusted by the platform itself
            # (e.g. additional immutable all-tenants-domain members appearing asynchronously), so
            # the whole field is excluded from the changed-comparison to avoid perpetual
            # false-positive drift.
            if is_ndo_5_2_or_later:
                ignore_keys.append("userAssociations")

            if mso.check_changed(ignore_keys=ignore_keys):
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
