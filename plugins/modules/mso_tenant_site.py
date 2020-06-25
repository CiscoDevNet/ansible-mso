#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_tenant_site
short_description: Manage tenants with cloud sites
description:
- Manage tenants with cloud sites on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
version_added: '2.8'
options:
  tenant:
    description:
    - The name of the tenant
    type: str
    required: yes
    aliases: [ name ]
  site:
    description:
    - The name of the site
    - This can either be cloud site or non-cloud site
    type: str
    aliases: [ name ]
  cloud_account:
    description:
    - Account id of AWS in the form '000000000000'.
    - Account id of Azure in the form 'uni/tn-(tenant_name)/act-[(subscriptionId)]-azure_vendor-azure'.
    type: str
  security_domains:
    description:
    - List of security domains for cloud sites
    type: list
    default: []
  aws_trusted:
    description:
    - AWS account's access in trusted mode. Set to true if no credentials are required.
    type: bool
  azure_access_type:
    description:
    - Managed mode for Azure
    - Credentials mode for Azure
    - Shared mode if the attribute is not specified
    choices: [ managed, credentials ]
    type: str
  azure_active_directory_id:
    description:
    - Azure account's active directory id
    - This attribute is required when azure_access_type is in credentials mode
    type: str
  aws_access_key:
    description:
    - AWS account's access key id
    type: str
  aws_account_org:
    description:
    - AWS account for organization
    type: bool
  azure_active_directory_name:
    description:
    - Azure account's active directory name
    - This attribute is required when azure_access_type is in credentials mode
    type: str
  azure_subscription_id:
    description:
    - Azure account's subscription id.
    - This attribute is required when azure_access_type is in manged mode
    - This attribute is required when azure_access_type is in credentials mode
    type: str
  azure_application_id:
    description:
    - Azure account's application id
    - This attribute is required when azure_access_type is in manged mode
    - This attribute is required when azure_access_type is in credentials mode
    type: str
  azure_credential_name:
    description:
    - Azure account's credential name
    - This attribute is required when azure_access_type is in credentials mode
    type: str
  secret_key:
    description:
    - secret key of AWS for untrusted account. Required in untrusted mode of AWS account.
    - secret key of Azure for unmanaged identity. Required in unmanged mode of Azure account.
    type: str
  azure_vendor:
    description:
    - This is an azure attribute
    default: azure
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
'''

EXAMPLES = r'''
- name: Associate a non-cloud site with a tenant
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: ansible_test
    state: present
  delegate_to: localhost

- name: Associate aws site with a tenant
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: aws
    cloud_account: '000000000000'
    aws_trusted: false
    aws_access_key: 1
    secret_key: 0
    aws_account_org: false
    state: present
  delegate_to: localhost

- name: Associate azure site in credentials mode
  mso.cisco.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: azure
    azure_subscription_id: 9
    azure_application_id: 100
    azure_credential_name: cApicApp
    secret_key: iins
    azure_active_directory_id: 32
    azure_active_directory_name: CiscoINSBUAd
    azure_vendor: azure
    cloud_account: uni/tn-ansible_test/act-[9]-azure_vendor-azure
    azure_access_type: credentials
    state: present
  delegate_to: localhost

- name: Dissociate aws site
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: aws
    state: absent
  delegate_to: localhost

- name: Dissociate azure site
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: azure
    state: absent
  delegate_to: localhost

- name: Query aws tenant
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    site: aws
    state: query
  delegate_to: localhost

- name: Query all sites
  cisco.mso.mso_tenant_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    state: query
  delegate_to: localhost
  register: query_result
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, issubset


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        tenant=dict(type='str', aliases=['name'], required=True),
        site=dict(type='str', aliases=['name']),
        cloud_account=dict(type='str'),
        azure_vendor=dict(type='str', default='azure'),
        security_domains=dict(type='list', default=[]),
        aws_trusted=dict(type='bool'),
        azure_access_type=dict(type='str', choices=['managed', 'credentials']),
        azure_active_directory_id=dict(type='str'),
        aws_access_key=dict(type='str'),
        aws_account_org=dict(type='bool'),
        azure_active_directory_name=dict(type='str'),
        azure_subscription_id=dict(type='str'),
        azure_application_id=dict(type='str'),
        azure_credential_name=dict(type='str'),
        secret_key=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present', 'query']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'absent', ['tenant', 'site']],
            ['state', 'present', ['tenant', 'site']],
        ],
    )

    state = module.params.get('state')
    security_domains = module.params.get('security_domains')
    azure_vendor = module.params.get('azure_vendor')
    cloud_account = module.params.get('cloud_account')
    azure_access_type = module.params.get('azure_access_type')
    azure_credential_name = module.params.get('azure_credential_name')
    azure_application_id = module.params.get('azure_application_id')
    azure_active_directory_id = module.params.get('azure_active_directory_id')
    azure_active_directory_name = module.params.get('azure_active_directory_name')
    azure_subscription_id = module.params.get('azure_subscription_id')
    secret_key = module.params.get('secret_key')
    aws_account_org = module.params.get('aws_account_org')
    aws_access_key = module.params.get('aws_access_key')
    aws_trusted = module.params.get('aws_trusted')

    mso = MSOModule(module)

    # Get tenant_id and site_id
    tenant_id = mso.lookup_tenant(module.params.get('tenant'))
    site_id = mso.lookup_site(module.params.get('site'))
    tenants = [(t.get('id')) for t in mso.query_objs('tenants')]
    tenant_idx = tenants.index((tenant_id))

    # set tenent and port paths
    tenant_path = 'tenants/{0}'.format(tenant_id)
    ops = []
    ports_path = '/siteAssociations/-'
    port_path = '/siteAssociations/{0}'.format(site_id)

    payload = dict(
        siteId=site_id,
        securityDomains=security_domains,
        cloudAccount=cloud_account,
    )

    if not cloud_account:
        payload = payload

    if cloud_account is not None:
        if 'azure' in cloud_account:
            if azure_access_type is None:
                payload = payload

            if azure_access_type is not None:
                azure_account = dict(
                    accessType=azure_access_type,
                    securityDomains=security_domains,
                    vendor=azure_vendor,
                )

                payload['azureAccount'] = [azure_account]
                cloudSubscription = dict(cloudSubscriptionId=azure_subscription_id, cloudApplicationId=azure_application_id)
                payload['azureAccount'][0]['cloudSubscription'] = cloudSubscription
                cloudApplication = dict(cloudApplicationId=azure_application_id, cloudCredentialName=azure_credential_name,
                                        secretKey=secret_key, cloudActiveDirectoryId=azure_active_directory_id)
                cloudActiveDirectory = dict(cloudActiveDirectoryId=azure_active_directory_id, cloudActiveDirectoryName=azure_active_directory_name)

                if azure_access_type == 'managed':
                    if not azure_subscription_id:
                        mso.fail_json(msg="azure_susbscription_id is required when in managed mode.")
                    if not azure_application_id:
                        mso.fail_json(msg="azure_application_id is required when in managed mode.")
                    payload['azureAccount'][0]['cloudApplication'] = []
                    payload['azureAccount'][0]['cloudActiveDirectory'] = []

                if azure_access_type == 'credentials':
                    if not azure_subscription_id:
                        mso.fail_json(msg="azure_subscription_id is required when in credentials mode.")
                    if not azure_application_id:
                        mso.fail_json(msg="azure_application_id is required when in credentials mode.")
                    if not secret_key:
                        mso.fail_json(msg="secret_key is required when in credentials mode.")
                    if not azure_active_directory_id:
                        mso.fail_json(msg="azure_active_directory_id is required when in credentials mode.")
                    if not azure_active_directory_name:
                        mso.fail_json(msg="azure_active_directory_name is required when in credentials mode.")
                    if not azure_credential_name:
                        mso.fail_json(msg="azure_credential_name is required when in credentials mode.")
                    payload['azureAccount'][0]['cloudApplication'] = [cloudApplication]
                    payload['azureAccount'][0]['cloudActiveDirectory'] = [cloudActiveDirectory]

        else:
            aws_account = dict(
                accountId=cloud_account,
                isTrusted=aws_trusted,
                accessKeyId=aws_access_key,
                secretKey=secret_key,
                isAccountInOrg=aws_account_org,
            )
            if not aws_trusted:
                if not aws_access_key:
                    mso.fail_json(msg="aws_access_key is a required field in untrusted mode.")
                if not secret_key:
                    mso.fail_json(msg="secret_key is a required field in untrusted mode.")
            payload['awsAccount'] = [aws_account]

    sites = [(s.get('siteId')) for s in mso.query_objs('tenants')[tenant_idx]['siteAssociations']]

    if site_id not in sites:
        mso.existing = {}
    else:
        site_idx = sites.index((site_id))
        mso.existing = mso.query_objs('tenants')[tenant_idx]['siteAssociations'][site_idx]

    if state == 'query':
        if len(sites) == 0:
            mso.fail_json(msg="No site associated with tenant Id {0}".format(tenant_id))
        elif site_id in sites:
            mso.existing = mso.query_objs('tenants')[tenant_idx]['siteAssociations'][site_idx]
        elif site_id not in sites and site_id is not None:
            mso.fail_json(msg="Site Id {0} not associated with tenant Id {1}".format(site_id, tenant_id))
        elif site_id is None:
            mso.existing = mso.query_objs('tenants')[tenant_idx]['siteAssociations']
        mso.exit_json()

    mso.previous = mso.existing

    if state == 'absent':
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op='remove', path=port_path))
    if state == 'present':
        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op='replace', path=port_path, value=mso.sent))
        else:
            ops.append(dict(op='add', path=ports_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(tenant_path, method='PATCH', data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
