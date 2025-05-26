#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_fabric_span_session_source
short_description: Manage Fabric SPAN Sessions Source on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Switched Port Analyzer (SPAN) Sessions Source on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.4) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Monitoring Access Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Fabric Monitoring Access Policy template.
    - This parameter or O(template) is required.
    type: str
  span_session_name:
    description:
    - The name of the SPAN Session.
    - This parameter or O(span_session_uuid) is required.
    type: str
  span_session_uuid:
    description:
    - The UUID of the SPAN Session.
    - This parameter or O(span_session_name) is required.
    type: str
  name:
    description:
    - The name of the SPAN Session source.
    type: str
  direction:
    description:
    - The direction of the SPAN Session source.
    - Defaults to C(incoming) when unset during creation.
    type: str
    choices: [ incoming, outgoing, both ]
  span_drop_packets:
    description:
    - The SPAN Drop Packets of the SPAN Session source.
    - Defaults to false when unset during creation.
    - The O(filter_epg) and O(filter_l3out) is not configurable when this parameter set to true.
    type: bool
  filter_epg:
    description:
    - The Filter EPG of the SPAN Session source.
    type: dict
    suboptions:
      enabled:
        description:
        - This parameter is used to clear the Filter EPG configuration.
        type: bool
      epg_uuid:
        description:
        - The UUID of the EPG used to configure the Filter EPG.
        - This parameter or O(filter_epg.epg) is required.
        type: str
      epg:
        description:
        - The EPG object detail used to configure the Filter EPG.
        - This parameter or O(filter_epg.epg_uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name of the EPG.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the EPG.
            - This parameter or O(filter_epg.epg.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the EPG.
            - This parameter or O(filter_epg.epg.template) is required.
            type: str
          schema_id:
            description:
            - The ID of the schema that contains the EPG.
            - This parameter or O(filter_epg.epg.schema) is required.
            type: str
          schema:
            description:
            - The name of the schema that contains the EPG.
            - This parameter or O(filter_epg.epg.schema_id) is required.
            type: str
          anp:
            description:
            - The name of the ANP that contains the EPG.
            - This parameter or O(filter_epg.epg.anp_uuid) is required.
            type: str
          anp_uuid:
            description:
            - The UUID of the ANP that contains the EPG.
            - This parameter or O(filter_epg.epg.anp) is required.
            type: str
  filter_l3out:
    description:
    - The Filter L3Out of the SPAN Session source.
    type: dict
    suboptions:
      enabled:
        description:
        - This parameter is used to clear the Filter L3Out configuration.
        type: bool
      tenant:
        description:
        - The name of the tenant. This parameter is used to associate the L3Out from APIC.
        type: str
      l3out:
        description:
        - The name of the L3Out.
        - This parameter or O(filter_l3out.l3out_uuid) is required.
        type: str
      l3out_uuid:
        description:
        - The UUID of the L3Out.
        - This parameter or O(filter_l3out.l3out) is required.
        type: str
      vlan_id:
        description:
        - The ID of the VLAN, which is associated with L3Out interface.
        - This parameter is required to configure the Filter L3Out.
        type: int
      template:
        description:
        - The name of the L3Out template.
        - This parameter or O(filter_l3out.template_id) is required to associate the L3Out from L3Out template.
        type: str
      template_id:
        description:
        - The ID of the L3Out template.
        - This parameter or O(filter_l3out.template) is required to associate the L3Out from L3Out template.
        type: str
  access_paths:
    description:
    - The Access Path of the SPAN Session source.
    - Providing a new list of O(access_paths) will completely replace an existing one from the SPAN Session source.
    - Providing an empty list will remove the O(access_paths=[]) from the SPAN Session source.
    type: list
    elements: dict
    suboptions:
      access_path_type:
        description:
        - The type of the Access Path.
        type: str
        choices: [ port, port_channel, virtual_port_channel, vpc_component_pc ]
      uuid:
        description:
        - The UUID of the 'Access Port' or 'Port Channel' or 'Virtual Port Channel' which is used to create the Access Path.
        type: str
      node:
        description:
        - The ID of the Node. This parameter is required to configure the 'Access Port' or 'Virtual Component PC' Access Path.
        type: int
      interface:
        description:
        - The interface of the Node. This parameter is required to configure the 'Access Port' Access Path.
        type: str
      name:
        description:
        - The name of the 'Port Channel' or 'Virtual Port Channel' which is used to create the Access Path.
        type: str
      template:
        description:
        - The name of the Fabric Resource Policy template.
        - This parameter or O(access_paths.template_id) is required to configure the 'Port Channel' or 'Virtual Port Channel' Access Path.
        type: str
      template_id:
        description:
        - The ID of the Fabric Resource Policy template.
        - This parameter or O(access_paths.template) is required to configure the 'Port Channel' or 'Virtual Port Channel' Access Path.
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
  Use M(cisco.mso.ndo_template) to create the Fabric Monitoring Access Policy template.
- The O(span_session_name) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_fabric_span_session) to create the Fabric SPAN Session.
- The O(filter_epg.epg) must exist before using it with this module in your playbook.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the EPG.
- The O(filter_l3out.l3out) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out.
- The O(access_paths.name) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_port_channel_interface) to create the Fabric resource port channel interface.
- The O(access_paths.name) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_virtual_port_channel_interface) to create the Fabric resource virtual port channel interface.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_fabric_span_session
- module: cisco.mso.mso_schema_template_anp_epg
- module: cisco.mso.ndo_port_channel_interface
- module: cisco.mso.ndo_virtual_port_channel_interface
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create the SPAN Session source with access paths
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_2
    direction: outgoing
    span_drop_packets: true
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/6
      - access_path_type: port_channel
        name: ansible_test_pc1
        template: ansible_test_fabric_resource
      - access_path_type: virtual_port_channel
        name: ansible_test_vpc1
        template: ansible_test_fabric_resource
      - access_path_type: vpc_component_pc
        name: ansible_test_vpc1
        template: ansible_test_fabric_resource
        node: 101
    state: present
  register: add_ansible_test_source_2

- name: Create the SPAN Session source with access path and filter EPG
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_3
    direction: outgoing
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/6
    filter_epg:
      epg:
        schema: ansible_test_schema
        template: template1
        anp: ansible_test_anp
        name: ansible_test_epg1
    state: present

- name: Create the SPAN Session source with access path and filter L3Out
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_4
    direction: outgoing
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/1
    filter_l3out:
      l3out: ansible_test_l3out
      vlan_id: 41
      template: ansible_test_l3out_template
    state: present

- name: Create the SPAN Session source with access paths UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ add_span_session.current.templateId }}"
    span_session_uuid: "{{ add_span_session.current.uuid }}"
    name: ansible_test_source_1
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/1
      - access_path_type: port_channel
        uuid: "{{ add_fabric_pc_1.current.uuid }}"
      - access_path_type: virtual_port_channel
        uuid: "{{ add_fabric_vpc1.current.uuid }}"
      - access_path_type: vpc_component_pc
        uuid: "{{ add_fabric_vpc1.current.uuid }}"
        node: 101
    state: present

- name: Update the SPAN Session source Filter EPG using UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    direction: outgoing
    filter_epg:
      epg_uuid: "{{ add_epg.current.epg }}"
    state: present

- name: Update the SPAN Session source Filter L3Out using UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    direction: outgoing
    access_paths:
      - access_path_type: port_channel
        name: ansible_test_pc1
        template: ansible_test_fabric_resource
    filter_l3out:
      l3out_uuid: "{{ add_l3out.current.uuid }}"
      vlan_id: 42
    state: present

- name: Query a specific SPAN Session source
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    state: query
  register: query_one

- name: Query all SPAN Session sources
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    state: query
  register: query_all

- name: Delete the SPAN Session source
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, epg_object_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schemas import MSOSchemas
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        span_session_name=dict(type="str"),
        span_session_uuid=dict(type="str"),
        name=dict(type="str"),
        direction=dict(type="str", choices=["incoming", "outgoing", "both"]),
        span_drop_packets=dict(type="bool"),
        filter_epg=dict(
            type="dict",
            mutually_exclusive=[("epg", "epg_uuid")],
            required_one_of=[["epg", "epg_uuid", "enabled"]],
            options=dict(
                epg_uuid=dict(type="str"),
                epg=epg_object_reference_spec(),
                enabled=dict(type="bool"),
            ),
        ),
        filter_l3out=dict(
            type="dict",
            mutually_exclusive=[("l3out", "l3out_uuid"), ("tenant", "template", "template_id")],
            required_one_of=[["l3out", "l3out_uuid", "enabled"]],
            options=dict(
                enabled=dict(type="bool"),
                tenant=dict(type="str"),
                l3out=dict(type="str"),
                l3out_uuid=dict(type="str"),
                vlan_id=dict(type="int"),
                template=dict(type="str"),
                template_id=dict(type="str"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
        access_paths=dict(
            type="list",
            elements="dict",
            options=dict(
                uuid=dict(type="str"),
                node=dict(type="int"),
                interface=dict(type="str"),
                name=dict(type="str"),
                template=dict(type="str"),
                template_id=dict(type="str"),
                access_path_type=dict(type="str", choices=["port", "port_channel", "virtual_port_channel", "vpc_component_pc"]),
            ),
            mutually_exclusive=[("uuid", "interface", "name"), ("template", "template_id")],
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("span_session_name", "span_session_uuid"),
            ("filter_epg", "filter_l3out"),
        ],
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["span_session_name", "span_session_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_schemas = MSOSchemas(mso)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    span_session_name = module.params.get("span_session_name")
    span_session_uuid = module.params.get("span_session_uuid")
    name = module.params.get("name")
    direction = module.params.get("direction")
    span_drop_packets = module.params.get("span_drop_packets")
    filter_epg = module.params.get("filter_epg")
    filter_l3out = module.params.get("filter_l3out")
    access_paths = module.params.get("access_paths")
    state = module.params.get("state")

    errors = validate_access_paths(access_paths)
    if errors:
        mso.fail_json(msg=", ".join(errors))

    errors = validate_filter_l3out(filter_l3out)
    if errors:
        mso.fail_json(msg=", ".join(errors))

    mso_template = MSOTemplate(mso, "monitoring_tenant", template_name, template_id)
    mso_template.validate_template("monitoring")
    site_id = mso_template.template.get("monitoringTemplate").get("sites")[0].get("siteId")

    fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
    match = mso_template.get_fabric_span_session_source(name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []))

    if match and name:
        mso.existing = mso.previous = copy.deepcopy(
            set_fabric_span_session_source_object_details(mso_template, site_id, match.details)
        )  # Query a specific object
    elif match:
        mso.existing = [set_fabric_span_session_source_object_details(mso_template, site_id, obj) for obj in match]  # Query all objects

    if state != "query":
        source_path = "/monitoringTemplate/template/spanSessions/{0}/sourceGroup/sources/{1}".format(fabric_span_session.index, match.index if match else "-")

    ops = []

    if state == "present":
        mso_values = dict(
            name=name,
            direction=direction,
            spanDropPackets=span_drop_packets,
        )

        if filter_epg and (filter_epg.get("epg") or filter_epg.get("epg_uuid")):
            mso_values["epg"] = mso_schemas.get_epg_uuid(filter_epg.get("epg"), filter_epg.get("epg_uuid"))

        if filter_l3out and (filter_l3out.get("l3out") or filter_l3out.get("l3out_uuid")):
            mso_values["l3out"] = dict(
                encapType="vlan",
                encapValue=filter_l3out.get("vlan_id"),
            )
            if filter_l3out.get("l3out_uuid"):
                mso_values["l3out"]["ref"] = filter_l3out.get("l3out_uuid")
            elif filter_l3out.get("l3out") and filter_l3out.get("tenant"):
                mso_values["l3out"]["dn"] = "uni/tn-{0}/out-{1}".format(filter_l3out.get("tenant"), filter_l3out.get("l3out"))
            elif filter_l3out.get("l3out") and (filter_l3out.get("template") or filter_l3out.get("template_id")):
                l3out_template = mso_templates.get_template("l3out", filter_l3out.get("template"), filter_l3out.get("template_id"))
                l3out_match = l3out_template.get_l3out_object(uuid=filter_l3out.get("l3out_uuid"), name=filter_l3out.get("l3out"), fail_module=True)
                if l3out_match:
                    mso_values["l3out"]["ref"] = l3out_match.details.get("uuid")

        if access_paths:
            mso_values["accessPaths"] = update_access_paths(mso, site_id, access_paths, mso_templates)

        if match:
            mso_remove_values = []
            proposed_payload = copy.deepcopy(match.details)
            proposed_payload.update({"name": mso_values["name"], "direction": mso_values["direction"], "spanDropPackets": mso_values["spanDropPackets"]})

            if filter_epg and match.details.get("epg") and filter_epg.get("enabled") is False:
                mso_remove_values.append("epg")
                proposed_payload["epg"] = ""
                match.details.pop("epgName")
                match.details.pop("epgTemplateName")
                match.details.pop("epgTemplateId")
                match.details.pop("epgSchemaName")
                match.details.pop("epgSchemaId")
            elif mso_values.get("epg"):
                if match.details.get("l3out"):
                    mso_remove_values.append("l3out")
                proposed_payload["epg"] = mso_values["epg"]

            if filter_l3out and match.details.get("l3out") and filter_l3out.get("enabled") is False:
                mso_remove_values.append("l3out")
                proposed_payload["l3out"] = {}
                match.details["l3out"] = {}
            elif mso_values.get("l3out"):
                if match.details.get("epg"):
                    mso_remove_values.append("epg")
                proposed_payload["l3out"] = mso_values["l3out"]

            if access_paths == [] and match.details.get("accessPaths"):
                mso_remove_values.append("accessPaths")
                proposed_payload["accessPaths"] = []
                match.details["accessPaths"] = []
            elif mso_values.get("accessPaths"):
                proposed_payload["accessPaths"] = mso_values["accessPaths"]

            mso.sanitize(proposed_payload, collate=True)
            append_update_ops_data(ops, match.details, source_path, mso_values, mso_remove_values)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=source_path, value=mso.sent))

    elif state == "absent" and match:
        ops.append(dict(op="remove", path=source_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
        match = mso_template.get_fabric_span_session_source(name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []))
        if match:
            mso.existing = set_fabric_span_session_source_object_details(mso_template, site_id, match.details)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = set_fabric_span_session_source_object_details(mso_template, site_id, mso.proposed) if state == "present" else {}

    mso.exit_json()


def validate_filter_l3out(filter_l3out):
    if filter_l3out:
        errors = []
        if filter_l3out.get("l3out"):
            if not filter_l3out.get("vlan_id"):
                errors.append("The 'vlan_id' is required when 'l3out' is set.")
            if not (filter_l3out.get("tenant") or filter_l3out.get("template") or filter_l3out.get("template_id")):
                errors.append("At least one of 'tenant', 'template', or 'template_id' is required when 'l3out' is set.")
        elif filter_l3out.get("l3out_uuid"):
            if not filter_l3out.get("vlan_id"):
                errors.append("The 'vlan_id' is required when 'l3out_uuid' is set.")
        return errors


def validate_access_paths(access_paths):
    if access_paths:
        errors = []
        for index, path in enumerate(access_paths):
            access_path_type = path.get("access_path_type")
            uuid = path.get("uuid")
            node = path.get("node")
            interface = path.get("interface")
            name = path.get("name")
            template = path.get("template")
            template_id = path.get("template_id")

            # Validate based on access_path_type
            if access_path_type == "port":
                if not uuid and not (node and interface):
                    errors.append(
                        "Access path {0}: when the access_path_type='port', either 'uuid' or both 'node' and 'interface' must be provided.".format(index + 1)
                    )

            elif access_path_type == "port_channel":
                if not uuid and not (name and template) and not (name and template_id):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type='port_channel', either 'uuid',"
                            + " or both 'name' and 'template', or both 'name' and 'template_id' must be provided."
                        ).format(index + 1)
                    )

            elif access_path_type == "virtual_port_channel":
                if not uuid and not (name and template) and not (name and template_id):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type 'virtual_port_channel', either 'uuid',"
                            + " or both 'name' and 'template', or both 'name' and 'template_id' must be provided."
                        ).format(index + 1)
                    )

            elif access_path_type == "vpc_component_pc":
                if not (uuid and node) and not (name and template and node) and not (name and template_id and node):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type 'vpc_component_pc', either both 'uuid' and 'node',"
                            + " or all of 'name', 'template', and 'node',"
                            + " or all of 'name', 'template_id', and 'node' must be provided."
                        ).format(index + 1)
                    )
        return errors


def get_access_path_payload(mso_templates, access_path_config, access_path_type, resource_type):
    uuid = access_path_config.get("uuid")
    if not uuid:
        fabric_template = mso_templates.get_template("fabric_resource", access_path_config.get("template"), access_path_config.get("template_id"))
        uuid = fabric_template.get_template_policy_uuid("fabric_resource", access_path_config.get("name"), resource_type)

    return (
        dict(vpcComponentPc=[dict(vpc=uuid, node=str(access_path_config.get("node")))]) if access_path_type == "vpc_component_pc" else {resource_type: [uuid]}
    )


def update_access_paths(mso, site_id, access_paths, mso_templates):
    updated_paths = []
    for access_path in access_paths:
        if access_path.get("access_path_type") == "port":
            port_uuid = access_path.get("uuid")
            if not port_uuid:
                port_uuid = mso.get_site_interface_details(
                    site_id=site_id,
                    uuid=None,
                    node=access_path.get("node"),
                    port=access_path.get("interface"),
                ).get("uuid")
            updated_paths.append(dict(accessInterfaces=[port_uuid]))

        elif access_path.get("access_path_type") == "port_channel":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "port_channel", "portChannels"))

        elif access_path.get("access_path_type") == "virtual_port_channel":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "virtual_port_channel", "virtualPortChannels"))

        elif access_path.get("access_path_type") == "vpc_component_pc":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "vpc_component_pc", "virtualPortChannels"))

    # Remove duplicates
    unique_paths = {str(path): path for path in updated_paths}.values()
    return list(unique_paths)


def set_fabric_span_session_source_object_details(mso_template, site_id, source):
    if source:
        for access_path in source.get("accessPaths", []):  # Adding the object reference name to use the update_config_with_template_and_references function
            if access_path.get("accessInterfaces") and isinstance(access_path.get("accessInterfaces")[0], str):
                access_path.get("accessInterfaces")[0] = mso_template.mso.get_site_interface_details(site_id, access_path.get("accessInterfaces")[0])
            elif access_path.get("portChannels") and isinstance(access_path.get("portChannels")[0], str):
                access_path.get("portChannels")[0] = dict(portChannel=access_path.get("portChannels")[0])
            elif access_path.get("virtualPortChannels") and isinstance(access_path.get("virtualPortChannels")[0], str):
                access_path.get("virtualPortChannels")[0] = dict(virtualPortChannel=access_path.get("virtualPortChannels")[0])

        source.update({"templateId": mso_template.template_id, "templateName": mso_template.template_name})
        reference_details = {
            "filterEPG": {
                "name": "epgName",
                "reference": "epg",
                "type": "epg",
                "template": "epgTemplateName",
                "templateId": "epgTemplateId",
                "schema": "epgSchemaName",
                "schemaId": "epgSchemaId",
            },
            "portChannels": {
                "name": "portChannelName",
                "reference": "portChannel",
                "type": "portChannel",
                "template": "portChannelTemplateName",
                "templateId": "portChannelTemplateId",
            },
            "virtualPortChannels": {
                "name": "virtualPortChannelName",
                "reference": "virtualPortChannel",
                "type": "virtualPortChannel",
                "template": "virtualPortChannelTemplateName",
                "templateId": "virtualPortChannelTemplateId",
            },
            "vpcComponentPc": {
                "name": "vpcComponentPcName",
                "reference": "vpc",
                "type": "virtualPortChannel",
                "template": "vpcComponentPcTemplateName",
                "templateId": "vpcComponentPcTemplateId",
            },
        }

        mso_template.update_config_with_template_and_references(source, reference_details, False)
    return source


if __name__ == "__main__":
    main()
