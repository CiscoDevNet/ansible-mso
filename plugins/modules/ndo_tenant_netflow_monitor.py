#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_netflow_monitor
version_added: "2.12.0"
short_description: Manage NetFlow Monitor on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage NetFlow Monitor on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v4.1 and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the tenant template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the NetFlow Monitor.
    type: str
  uuid:
    description:
    - The UUID of the NetFlow Monitor.
    - This parameter is required when the O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the NetFlow Monitor.
    - Defaults to an empty string when unset during creation.
    type: str
  netflow_record:
    description:
    - The NetFlow Record reference details for the NetFlow Monitor.
    - Providing an empty dictionary O(netflow_record={}) will remove NetFlow Record from the NetFlow Monitor.
    - Defaults to an empty string when unset during creation.
    type: dict
    suboptions:
      uuid:
        description:
        - The UUID of the NetFlow Record.
        - This parameter can be used instead of O(netflow_record.reference).
        type: str
      reference:
        description:
        - The reference details of the NetFlow Record.
        - This parameter can be used instead of O(netflow_record.uuid).
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the NetFlow Record.
            type: str
            required: True
          template:
            description:
            - The template associated with the NetFlow Record.
            - This parameter or O(netflow_record.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The template ID associated with the NetFlow Record.
            - This parameter or O(netflow_record.reference.template) is required.
            type: str
  netflow_exporters:
    description:
    - The list of NetFlow Exporter references.
    - At least one reference is required when the state is C(present).
    - The old O(netflow_exporters) list will be replaced by the new list during an update.
    type: list
    elements: dict
    suboptions:
      uuid:
        description:
        - The UUID of the NetFlow Exporter.
        - This parameter or O(netflow_exporters.reference) is required.
        type: str
      reference:
        description:
        - The reference of the NetFlow Exporter.
        - This parameter or O(netflow_exporters.uuid) is required.
        aliases: [ ref ]
        type: dict
        suboptions:
          name:
            description:
            - The name of the NetFlow Exporter.
            type: str
            required: True
          template:
            description:
            - The template associated with the NetFlow Exporter.
            - This parameter or O(netflow_exporters.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The template ID associated with the NetFlow Exporter.
            - This parameter or O(netflow_exporters.reference.template) is required.
            type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(netflow_record) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_tenant_netflow_record) to create the NetFlow Record.
- The O(netflow_exporters) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_tenant_netflow_exporter) to create the NetFlow Exporter.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_tenant_netflow_record
- module: cisco.mso.ndo_tenant_netflow_exporter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a NetFlow Monitor
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: netflow_monitor_1
    description: NetFlow Monitor for testing
    netflow_record:
      reference:
        name: netflow_record_1
        template: ansible_tenant_template
    netflow_exporters:
      - reference:
          name: netflow_exporter_1
          template: ansible_tenant_template
    state: present
  register: add_netflow_monitor

- name: Update a NetFlow Monitor name using UUID
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: netflow_monitor_1_updated
    uuid: "{{ add_netflow_monitor.current.uuid }}"
    netflow_exporters:
      - reference:
          name: netflow_exporter_1
          template: ansible_tenant_template
      - uuid: "{{ add_netflow_exporter_2.current.uuid }}"
    state: present

- name: Query a NetFlow Monitor using name
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: netflow_monitor_1_updated
    state: query
  register: query_one_with_name

- name: Query a NetFlow Monitor using UUID
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ add_netflow_monitor.current.uuid }}"
    state: query
  register: query_one_with_uuid

- name: Query all NetFlow Monitors
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Remove a NetFlow Monitor using name
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: netflow_monitor_1_updated
    state: absent

- name: Remove a NetFlow Monitor using UUID
  cisco.mso.ndo_tenant_netflow_monitor:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ add_netflow_monitor.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, ndo_template_object_spec_with_uuid
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str"),
        uuid=dict(type="str"),
        description=dict(type="str"),
        netflow_record=dict(type="dict", **ndo_template_object_spec_with_uuid(required_uuid_and_reference=False)),
        netflow_exporters=dict(type="list", elements="dict", **ndo_template_object_spec_with_uuid()),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
            ["state", "present", ["netflow_exporters"]],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = mso.params.get("template")
    template_id = mso.params.get("template_id")
    name = mso.params.get("name")
    uuid = mso.params.get("uuid")
    description = module.params.get("description")
    netflow_record = module.params.get("netflow_record")
    netflow_exporters = module.params.get("netflow_exporters")
    state = module.params.get("state")

    reference_details = {
        "netFlowExporter": {
            "name": "exporterName",
            "reference": "exporterRef",
            "type": "netFlowExporter",
            "template": "exporterTemplateName",
            "templateId": "exporterTemplateId",
        },
        "netFlowRecord": {
            "name": "recordName",
            "reference": "recordRef",
            "type": "netFlowRecord",
            "template": "recordTemplateName",
            "templateId": "recordTemplateId",
        },
    }

    ops = []
    match = None
    path = None

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    match = mso_template.get_netflow_monitor(uuid, name)

    if (uuid or name) and match:  # Query a specific object
        netflow_monitor_object = copy.deepcopy(match.details)
        netflow_monitor_object["exporterRefs"] = netflow_exporters_list_to_dict(netflow_monitor_object.get("exporterRefs"))
        updated_netflow_monitor_object = mso_template.update_config_with_template_and_references(netflow_monitor_object, reference_details, False)
        mso.previous = copy.deepcopy(updated_netflow_monitor_object)
        mso.existing = copy.deepcopy(updated_netflow_monitor_object)
    elif match:  # Query all objects
        for obj in match:
            obj["exporterRefs"] = netflow_exporters_list_to_dict(obj.get("exporterRefs"))

        mso.existing = [mso_template.update_config_with_template_and_references(obj, reference_details, False) for obj in match]

    if state != "query":
        path = "/tenantPolicyTemplate/template/netFlowMonitors/{0}".format(match.index if match else "-")

    if state == "present":
        netflow_record_uuid = None
        if netflow_record:
            netflow_record_uuid = netflow_record.get("uuid")
            netflow_record_reference = netflow_record.get("reference")
            if not netflow_record_uuid and netflow_record_reference and not check_if_all_elements_are_none(netflow_record_reference.values()):
                netflow_record_template = mso_templates.get_template(
                    "tenant", netflow_record_reference.get("template"), netflow_record_reference.get("template_id")
                )
                netflow_record_match = netflow_record_template.get_netflow_record(
                    uuid=None, name=netflow_record_reference.get("name"), search_object=None, fail_module=True
                )
                netflow_record_uuid = netflow_record_match.details.get("uuid")

        netflow_exporter_uuids = []
        for netflow_exporter in netflow_exporters:
            if netflow_exporter and netflow_exporter.get("uuid"):
                netflow_exporter_uuids.append(netflow_exporter.get("uuid"))
            elif netflow_exporter and not check_if_all_elements_are_none(netflow_exporter.get("reference", {}).values()):
                ref = netflow_exporter.get("reference")
                netflow_exporter_template = mso_templates.get_template("tenant", ref.get("template"), ref.get("template_id"))
                netflow_exporter_match = netflow_exporter_template.get_netflow_exporter(uuid=None, name=ref.get("name"), search_object=None, fail_module=True)
                netflow_exporter_uuids.append(netflow_exporter_match.details.get("uuid"))

        mso_values = {
            "name": name,
            "description": description,
            "exporterRefs": netflow_exporter_uuids,
            "recordRef": netflow_record_uuid if netflow_record_uuid else "",
        }

        if match:
            append_update_ops_data(ops, match.details, path, mso_values)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path, value=mso.sent))

    elif state == "absent" and match:
        ops.append(dict(op="remove", path=path))

    if mso.proposed:
        mso.proposed = copy.deepcopy(mso.proposed)
        mso.proposed["exporterRefs"] = netflow_exporters_list_to_dict(mso.proposed.get("exporterRefs", []))
        proposed_reference_details = copy.deepcopy(reference_details)
        if mso.proposed.get("recordRef") == "":
            proposed_reference_details.pop("recordRef", None)
        mso_template.update_config_with_template_and_references(mso.proposed, proposed_reference_details, False)

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_netflow_monitor(uuid, name, response)
        if match:
            match.details["exporterRefs"] = netflow_exporters_list_to_dict(match.details.get("exporterRefs"))
            mso.existing = mso_template.update_config_with_template_and_references(match.details, reference_details, False)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent

    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def netflow_exporters_list_to_dict(netflow_exporters):
    return [{"exporterRef": mr} for mr in netflow_exporters]


if __name__ == "__main__":
    main()
