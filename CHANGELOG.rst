==========================================
Cisco MSO Ansible Collection Release Notes
==========================================

.. contents:: Topics

This changelog describes changes after version 0.0.4.

v1.0.0
======

Release Summary
---------------

This is the first official release of the ``cisco.mso`` collection on 2020-08-18.
This changelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0.


Minor Changes
-------------

- Add changelog
- Fix M() and module to use FQCN
- Update Ansible version in CI and add 2.10.0 to sanity in CI.
- Update Readme with supported versions

Bugfixes
--------

- Fix sanity issues to support 2.10.0

v0.0.8
======

Release Summary
---------------

New release v0.0.8

Minor Changes
-------------

- Add Login Domain support to mso_site
- Add aliases file for contract_filter module
- Add contract information in current and previous part
- Add new module and test file to query MSO version
- New backup module and test file (https://github.com/CiscoDevNet/ansible-mso/pull/80)
- Renaming mso_schema_template_externalepg module to mso_schema_template_external_epg while keeping both working.
- Update cidr module, udpate attributes in hub network module and its test file
- Use a function to reuuse duplicate part

Bugfixes
--------

- Add login_domain to existing test.
- Add missing tests for VRF settings and changing those settings.
- Add test for specifying read-only roles and increase overall test coverage of mso_user (https://github.com/CiscoDevNet/ansible-mso/pull/77)
- Add test to mso_schema_template_vrf, mso_schema_template_external_epg and mso_schema_template_anp_epg to check for API error when pushing changes to object with existing contract.
- Cleanup unused imports, unused variables and branches and change a variable from ambiguous name to reduce warnings at Ansible Galaxy import
- Fix API error when pushing EPG with existing contracts
- Fix role tests to work with pre/post 2.2.4 and re-enable them
- Fix site issue if no site present and fix test issues with MSO v3.0
- Fixing External EPG renaming for 2.9 and later
- Fixing L3MCast test to pass on 2.2.4
- Fixing wrong removal of schemas
- Test hub network module after creating region manually
- Updating Azure site IP in inventory and add second MSO version to inventory

v0.0.7
======

Release Summary
---------------

New release v0.0.7

Minor Changes
-------------

- Add l3out, preferred_group and test file for mso_schema_template_externalepg
- Add mso_schema_template_vrf_contract module and test file
- Add new attribute choice "policy_compression" to mso_Schema_template_contract_filter
- Add new functionality - Direct Port Channel (dpc), micro-seg-vlan and default values
- Add new module for anp-epg-selector in site level
- Add new module mso_schema_template_anp_epg_selector and its test file
- Add new module mso_schema_vrf_contract
- Add new module mso_tenant_site to support cloud and non-cloud sites association with a tenant and test file (https://github.com/CiscoDevNet/ansible-mso/pull/62)
- Add new mso_site_external_epg_selector module and test file
- Add site external epg and contract filter test
- Add support for VGW attribute in mso_schema_site_vrf_region_cidr_subnet
- Add support to set account as inactive using account_status attribute in mso_user
- Add test for mso_schema_site_vrf_region_cidr module
- Add test for mso_schema_site_vrf_region_cidr_subnet module
- Add vzAny attribute in mso_schema_template_vrf
- Automatically add ANP and EPG at site level and new test file for mso_schema_site_anp_epg_staticport (https://github.com/CiscoDevNet/ansible-mso/pull/55)
- Modified External EPG module and addition of new Selector module

Bugfixes
--------

- Fix mso_schema_site_vrf_region_cidr to automatically create VRF and Region if not present at site level
- Fix query condition when VRF or Region do not exist at site level
- Remove unused regions attribute from mso_schema_template_vrf

v0.0.6
======

Release Summary
---------------

New release v0.0.6

Minor Changes
-------------

- ACI/MSO - Use get() dict lookups (https://github.com/ansible/ansible/pull/63074)
- Add EPG and ANP at site level when needed
- Add github action CI pipeline with test coverage
- Add login domain support for authentication in all modules
- Add support for DHCP querier to all subnet objects. Add partial test in mso_schema_template_bd integration test.
- Add support for clean output if needed for debuging
- Add test file for mso_schema_template_anp_epg
- Added DHCP relay options and scope options to MSO schema template bd
- Added ability to bind epg to static fex port
- Added module to manage contracts for external EPG in Cisco MSO (https://github.com/ansible/ansible/pull/63550)
- Added module to manage template external epg subnet for Cisco MSO (https://github.com/ansible/ansible/pull/63542)
- Disabling tests for the role modules as API is not supported after 2.2.3i until further notice
- Increased test coverage for existing module integration tests.
- Modified fail messages for site and updated documentation
- Moving test to Ansible v2.9.9 and increasing timelimit for mutex to 30+ min
- Update authors.
- Update mso_schema_site_anp.py (https://github.com/ansible/ansible/pull/67099)
- Updated Test File Covering all conditions
- mso_schema_site_anp_epg_staticport - Add VPC support (https://github.com/ansible/ansible/pull/62803)

Bugfixes
--------

- Add aliases for backward support of permissions in role module.
- Add integration test for mso_schema_template_db and fix un-needed push to API found by integration test.
- Consistent object output on domain_associations
- Fix EPG / External EPG Contract issue and create test for mso_schema_template_anp_epg_contract and mso_schema_template_external_epg_contract
- Fix contract filter issue and add contract-filter test file
- Fix duplicate user, add admin user to associated user list and update tenant test file
- Fix intersite_multicast_source attribute issue in mso_schema_template_anp_epg and add the proxy_arp argument.
- Fix mso_schema_template_anp_epg idempotancy for both EPG and EPG with contracts
- Remove label with test domain before create it
- Send context instead of vrf when vrf parameter is used
- Update mso_schema_template_bd.py example for BD in another schema

v0.0.5
======

Release Summary
---------------

New release v0.0.5
