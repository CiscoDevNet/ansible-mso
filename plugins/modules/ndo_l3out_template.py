#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_template
short_description: Manage L3Outs on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Outs on Cisco Nexus Dashboard Orchestrator (NDO).
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the L3Out template.
    type: str
    aliases: [ l3out_template ]
    required: true
  name:
    description:
    - The name of the L3Out.
    type: str
  uuid:
    description:
    - The uuid of the L3Out.
    - This parameter is required when the L3Out needs to be updated.
    type: str
  description:
    description:
    - The description of the L3Out.
    type: str
  vrf:
    description:
    - The VRF associated with the L3Out.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF.
        required: true
        type: str
      schema:
        description:
        - The name of the schema.
        required: true
        type: str
      template:
        description:
        - The name of the template.
        required: true
        type: str
  l3_domain:
    description:
    - The name of the L3 Domain.
    type: str
  target_dscp:
    description:
    - The DHCP Level of the L3Out.
    type: str
    choices:
      - af11
      - af12
      - af13
      - af21
      - af22
      - af23
      - af31
      - af32
      - af33
      - af41
      - af42
      - af43
      - cs0
      - cs1
      - cs2
      - cs3
      - cs4
      - cs5
      - cs6
      - cs7
      - expedited_forwarding
      - unspecified
      - voice_admit
  pim:
    description:
    - The protocol independent multicast (PIM) flag of the L3Out.
    - By default, PIM is disabled. To enable the PIM, Layer 3 Multicast must be enabled on the O(vrf).
    type: bool
  inbound_route_map:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with inbound route map when the O(routing_protocols) is "bgp".
    type: str
    aliases: [ import_route, inbound_route ]
  outbound_route_map:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with outbound route map when the O(routing_protocols) is "bgp".
    type: str
    aliases: [ export_route, outbound_route ]
  routing_protocols:
    description:
    - The routing protocols of the L3Out.
    type: list
    elements: str
    choices: [bgp, ospf]
  ospf_area_config:
    description:
    - The OSPF area configuration of the L3Out.
    aliases: [ ospf_config ]
    type: dict
    suboptions:
      ospf_area_id:
        description:
        - The area id of the OSPF area.
        type: str
        aliases: [ area_id ]
        required: true
      ospf_area_type:
        description:
        - The area type of the OSPF area.
        type: str
        choices: [regular, stub, nssa]
        aliases: [ area_type ]
        required: true
      ospf_cost:
        description:
        - The cost of the OSPF area.
        type: int
        aliases: [ cost ]
        required: true
      originate_summary_lsa:
        description:
        - This option is for OSPF NSSA or Stub area.
        - When this option is disabled, not only Type 4 and 5, but also Type 3 LSAs are not sent into the NSSA or Stub area by the border leaf.
        - Instead, the border leaf creates and sends a default route to the area.
        - If there is no Type 3 LSA in this area in the first place, a default route is not created.
        type: bool
        aliases: [ originate_lsa ]
      send_redistributed_lsas:
        description:
        - This option is for the OSPF NSSA (not-so-stubby area).
        - When this option is disabled. The redistributed routes are not sent into this NSSA area from the border leaf.
        - This is typically used when the O(ospf_area_config.originate_summary_lsa) option is also disabled.
        - Because disabling the O(ospf_area_config.originate_summary_lsa) option creates and sends a default route to the NSSA or stub area.
        type: bool
        aliases: [ redistributed_lsas ]
      suppress_forwarding_addr_translated_lsa:
        description:
        - This option is for OSPF NSSA (not-so-stubby area).
        - When an OSPF NSSA ABR (Area Border Router) translates a Type-7 LSA into a Type-5 LSA to send it across non-NSSA areas.
        - It typically includes the IP address of the originator ASBR (Autonomous System Boundary Router) as a forwarding address.
        - However, if an OSPF router receiving the Type-5 LSA lacks a route to this forwarding address.
        - The route may not be installed in the router's route table.
        - Enabling this option prevents the ABR from adding a forwarding address during the Type-7 to Type-5 translation, thereby avoiding this issue.
        type: bool
        aliases: [ suppress_fa_lsa ]
  originate_default_route:
    description:
    - The Originate Default Route option in an L3Out configuration allows the ACI fabric to advertise a default route (0.0.0.0/0) to external networks.
    - The C("") used to clear the Originate Default Route option.
    type: str
    choices: [ only, inAddition, "" ]
  originate_default_route_always:
    description:
    - This option is applicable only if OSPF is configured on the L3Out.
    type: bool
    aliases: [ always ]
  advanced_route_map:
    description:
    - The advanced route map of the L3Out.
    type: dict
    suboptions:
      interleak:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Interleak route map.
        type: str
      static_route_redistribution:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Static Route Redistribution route map.
        type: str
        aliases: [ static_route ]
      connected_route_redistribution:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Connected Route Redistribution route map.
        type: str
        aliases: [ connected_route ]
      attached_host_route_redistribution:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Attached Host Route Redistribution route map.
        type: str
        aliases: [ attached_host_route ]
      route_dampening_ipv4:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Route Dampening IPv4 route map.
        - This option is applicable only when the O(routing_protocols) is "bgp".
        type: str
        aliases: [ dampening_ipv4 ]
      route_dampening_ipv6:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Route Dampening IPv6 route map.
        - This option is applicable only when the O(routing_protocols) is "bgp".
        type: str
        aliases: [ dampening_ipv6 ]
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
- name: Create a new L3Out object
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    vrf:
      name: "VRF1"
      schema: "Schema1"
      template: "Template1"
    state: "present"

- name: Update a L3Out object with UUID
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "uuid"
    description: "updated description"
    state: "present"

- name: Query a L3Out object with name
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    state: "query"
  register: query_l3out_name

- name: Query a L3Out object with UUID
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "uuid"
    state: "query"
  register: query_l3out_uuid

- name: Query all L3Out objects
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    state: "query"
  register: query_all_l3out

- name: Delete a L3Out object with UUID
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "uuid"
    state: "absent"

- name: Delete a L3Out object with name
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    state: "absent"
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP, ROUTING_PROTOCOLS_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["l3out_template"]),
        name=dict(type="str"),
        uuid=dict(type="str"),
        description=dict(type="str"),
        vrf=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                schema=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
        ),
        l3_domain=dict(type="str"),
        target_dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        pim=dict(type="bool"),
        inbound_route_map=dict(type="str", aliases=["import_route", "inbound_route"]),
        outbound_route_map=dict(type="str", aliases=["export_route", "outbound_route"]),
        routing_protocols=dict(type="list", elements="str", choices=["bgp", "ospf"]),
        ospf_area_config=dict(
            type="dict",
            options=dict(
                ospf_area_id=dict(type="str", aliases=["area_id"], required=True),
                ospf_area_type=dict(
                    type="str",
                    choices=["regular", "stub", "nssa"],
                    aliases=["area_type"],
                    required=True,
                ),
                ospf_cost=dict(type="int", aliases=["cost"], required=True),
                send_redistributed_lsas=dict(type="bool", aliases=["redistributed_lsas"]),
                originate_summary_lsa=dict(type="bool", aliases=["originate_lsa"]),
                suppress_forwarding_addr_translated_lsa=dict(type="bool", aliases=["suppress_fa_lsa"]),
            ),
            aliases=["ospf_config"],
        ),
        originate_default_route=dict(type="str", choices=["only", "inAddition", ""]),
        originate_default_route_always=dict(type="bool", aliases=["always"]),
        advanced_route_map=dict(
            type="dict",
            options=dict(
                interleak=dict(type="str"),
                static_route_redistribution=dict(type="str", aliases=["static_route"]),
                connected_route_redistribution=dict(type="str", aliases=["connected_route"]),
                attached_host_route_redistribution=dict(type="str", aliases=["attached_host_route"]),
                route_dampening_ipv4=dict(type="str", aliases=["dampening_ipv4"]),
                route_dampening_ipv6=dict(type="str", aliases=["dampening_ipv6"]),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["vrf", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        mutually_exclusive=[["name", "uuid"]],
    )

    mso = MSOModule(module)

    l3out_template = module.params.get("l3out_template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    vrf_dict = module.params.get("vrf") if module.params.get("vrf") else {}
    l3_domain = module.params.get("l3_domain")
    target_dscp = TARGET_DSCP_MAP.get(module.params.get("target_dscp"))
    pim = module.params.get("pim")
    outbound_route_map = module.params.get("outbound_route_map")
    routing_protocols = sorted(module.params.get("routing_protocols") if module.params.get("routing_protocols") else [])
    ospf_area_config_dict = module.params.get("ospf_area_config") if module.params.get("ospf_area_config") else {}
    originate_default_route = module.params.get("originate_default_route")
    advanced_route_map_dict = module.params.get("advanced_route_map") if module.params.get("advanced_route_map") else {}

    originate_default_route_always = module.params.get("originate_default_route_always")

    state = module.params.get("state")

    l3out_identifier = None
    if state in ["absent", "present"]:
        l3out_identifier = "Name: {0}".format(name) if name is not None else "UUID: {0}".format(uuid)

    l3out_template_object = MSOTemplate(mso, "l3out", l3out_template)
    l3out_template_object.validate_template("l3out")
    l3out_template_id = l3out_template_object.template.get("templateId")

    tenant_id = tenant_name = None
    tenant_id = l3out_template_object.template_summary.get("tenantId")
    tenant_name = l3out_template_object.template_summary.get("tenantName")

    l3outs = l3out_template_object.template.get("l3outTemplate", {}).get("l3outs", [])

    if state in ["query", "absent"] and l3outs == []:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = l3outs

    l3out_object = (None, None)
    if l3outs and (name or uuid):
        l3out_kv_list = []

        if name:
            l3out_kv_list = [KVPair("name", name)]
        else:
            l3out_kv_list = [KVPair("uuid", uuid)]

        l3out_object = l3out_template_object.get_object_from_list(l3outs, l3out_kv_list)

    l3out_object_index = None
    if l3out_object[0]:
        l3out_object_index = l3out_object[0].index

        if not uuid:
            uuid = l3out_object[0].details.get("uuid")

        if not name:
            name = l3out_object[0].details.get("name")

        mso.existing = copy.deepcopy(l3out_object[0].details)
        mso.previous = copy.deepcopy(l3out_object[0].details)
        proposed_payload = copy.deepcopy(l3out_object[0].details)

    ops = []
    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="L3Out with the uuid: '{0}' not found".format(uuid))

        if routing_protocols == ["bgp"] and ospf_area_config_dict:  # con1 for create
            mso.fail_json(
                msg="Invalid configuration in L3Out '{0}', 'ospf_area_config' must be empty when the routing_protocols is bgp".format(l3out_identifier)
            )
        elif routing_protocols in (["ospf"], ["bgp", "ospf"]) and not ospf_area_config_dict:  # con3 for create
            mso.fail_json(
                msg="Invalid configuration in L3Out '{0}', 'ospf_area_config' must be specified when the routing_protocols is {1}".format(
                    l3out_identifier, routing_protocols
                )
            )
        elif routing_protocols == ["ospf"] and (advanced_route_map_dict.get("route_dampening_ipv4") or advanced_route_map_dict.get("route_dampening_ipv6")):
            mso.fail_json(
                msg=(
                    "Invalid configuration in L3Out '{0}', 'advanced_route_map.route_dampening_ipv4'"
                    + "'advanced_route_map.route_dampening_ipv6' must be empty when the routing_protocols is {1}"
                ).format(l3out_identifier, routing_protocols)
            )
        elif routing_protocols != ["ospf"] and originate_default_route_always is True:
            mso.fail_json(
                msg="Invalid configuration in L3Out '{0}', 'originate_default_route_always' must be 'false' when the routing_protocols is {1}".format(
                    l3out_identifier, routing_protocols
                )
            )

        templates_objects_path = "templates/objects"
        route_map_params = {"type": "routeMap", "tenant-id": tenant_id}
        route_map_path = l3out_template_object.generate_api_endpoint(templates_objects_path, **route_map_params)
        route_map_objects = mso.query_objs(route_map_path)

        vrf_ref = None
        if vrf_dict:
            vrf_object = l3out_template_object.get_vrf_object(vrf_dict, tenant_id, templates_objects_path)
            if pim and vrf_object.details.get("l3MCast") is False:
                mso.fail_json(
                    msg="Invalid configuration in L3Out '{0}', 'pim' cannot be enabled while using the VRF '{1}' with L3 Multicast disabled".format(
                        l3out_identifier, vrf_dict.get("name")
                    )
                )
            vrf_ref = vrf_object.details.get("uuid")

        if not mso.existing and name:  # Create new l3out
            payload = dict(name=name)

            payload["vrfRef"] = vrf_ref

            if description:
                payload["description"] = description

            if l3_domain:
                payload["l3domain"] = l3_domain

            if target_dscp:
                payload["targetDscp"] = target_dscp

            if pim is not None:
                payload["pim"] = pim

            if routing_protocols:
                payload["routingProtocol"] = ROUTING_PROTOCOLS_MAP.get(",".join(routing_protocols))

            if advanced_route_map_dict:
                payload["advancedRouteMapRefs"] = dict()

            if advanced_route_map_dict.get("interleak"):
                payload["advancedRouteMapRefs"]["interleakRef"] = l3out_template_object.get_route_map(
                    "interleak",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("interleak"),
                    route_map_objects,
                ).get("uuid", "")

            if advanced_route_map_dict.get("static_route_redistribution"):
                payload["advancedRouteMapRefs"]["staticRouteRedistRef"] = l3out_template_object.get_route_map(
                    "static_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("static_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

            if advanced_route_map_dict.get("connected_route_redistribution"):
                payload["advancedRouteMapRefs"]["connectedRouteRedistRef"] = l3out_template_object.get_route_map(
                    "connected_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("connected_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

            if advanced_route_map_dict.get("attached_host_route_redistribution"):
                payload["advancedRouteMapRefs"]["attachedHostRouteRedistRef"] = l3out_template_object.get_route_map(
                    "attached_host_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("attached_host_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

            if routing_protocols in (["bgp"], ["bgp", "ospf"]):
                if module.params.get("inbound_route_map"):
                    payload["importRouteMapRef"] = l3out_template_object.get_route_map(
                        "inbound_route_map",
                        tenant_id,
                        tenant_name,
                        module.params.get("inbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                payload["importRouteControl"] = True if payload.get("importRouteMapRef") else False

                if module.params.get("outbound_route_map"):
                    payload["exportRouteMapRef"] = l3out_template_object.get_route_map(
                        "outbound_route_map",
                        tenant_id,
                        tenant_name,
                        module.params.get("outbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                if advanced_route_map_dict.get("route_dampening_ipv4"):
                    payload["advancedRouteMapRefs"]["routeDampeningV4Ref"] = l3out_template_object.get_route_map(
                        "route_dampening_ipv4",
                        tenant_id,
                        tenant_name,
                        advanced_route_map_dict.get("route_dampening_ipv4"),
                        route_map_objects,
                    ).get("uuid", "")

                if advanced_route_map_dict.get("route_dampening_ipv6"):
                    payload["advancedRouteMapRefs"]["routeDampeningV6Ref"] = l3out_template_object.get_route_map(
                        "route_dampening_ipv6",
                        tenant_id,
                        tenant_name,
                        advanced_route_map_dict.get("route_dampening_ipv6"),
                        route_map_objects,
                    ).get("uuid", "")

            if originate_default_route:
                payload["defaultRouteLeak"] = dict(
                    originateDefaultRoute=originate_default_route,
                )

            if originate_default_route_always is not None:
                payload["defaultRouteLeak"]["always"] = originate_default_route_always

            if routing_protocols in (["ospf"], ["bgp", "ospf"]):
                payload["ospfAreaConfig"] = dict()

                payload["ospfAreaConfig"]["cost"] = ospf_area_config_dict.get("ospf_cost")
                payload["ospfAreaConfig"]["id"] = ospf_area_config_dict.get("ospf_area_id")
                payload["ospfAreaConfig"]["areaType"] = ospf_area_config_dict.get("ospf_area_type")

                redistribute = ospf_area_config_dict.get("send_redistributed_lsas")
                originate = ospf_area_config_dict.get("originate_summary_lsa")
                suppress_fa = ospf_area_config_dict.get("suppress_forwarding_addr_translated_lsa")

                control = dict()
                if redistribute is not None:  # Create
                    control["redistribute"] = redistribute

                if originate is not None:  # Create
                    control["originate"] = originate

                if suppress_fa is not None:  # Create
                    control["suppressFA"] = suppress_fa

                if control:
                    payload["ospfAreaConfig"]["control"] = control

            mso.sanitize(payload)
            ops = [dict(op="add", path="/l3outTemplate/l3outs/-", value=payload)]
        elif mso.existing:
            update_ops = []
            l3out_attrs_path = "/l3outTemplate/l3outs/{0}".format(l3out_object_index)

            if vrf_ref:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/vrfRef", value=vrf_ref))
                proposed_payload["vrfRef"] = vrf_ref

            if description is not None:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/description", value=description))
                proposed_payload["description"] = description

            if l3_domain is not None:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/l3domain", value=l3_domain))
                proposed_payload["l3domain"] = l3_domain

            if target_dscp is not None:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/targetDscp", value=target_dscp))
                proposed_payload["targetDscp"] = target_dscp

            if pim is not None:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/pim", value=pim))
                proposed_payload["pim"] = pim

            if routing_protocols:
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/routingProtocol", value=ROUTING_PROTOCOLS_MAP.get(",".join(routing_protocols))))
                proposed_payload["routingProtocol"] = ROUTING_PROTOCOLS_MAP.get(",".join(routing_protocols))

            if advanced_route_map_dict and not mso.existing.get("advancedRouteMapRefs"):
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs", value=dict()))
                proposed_payload["advancedRouteMapRefs"] = dict()

            if advanced_route_map_dict.get("interleak") is not None:
                interleak_ref = l3out_template_object.get_route_map(
                    "interleak",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("interleak"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/interleakRef", value=interleak_ref))
                proposed_payload["advancedRouteMapRefs"]["interleakRef"] = interleak_ref

            if advanced_route_map_dict.get("static_route_redistribution") is not None:
                static_route_redistribution_ref = l3out_template_object.get_route_map(
                    "static_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("static_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(
                    dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/staticRouteRedistRef", value=static_route_redistribution_ref)
                )
                proposed_payload["advancedRouteMapRefs"]["staticRouteRedistRef"] = static_route_redistribution_ref

            if advanced_route_map_dict.get("connected_route_redistribution") is not None:
                connected_route_redistribution_ref = l3out_template_object.get_route_map(
                    "connected_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("connected_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(
                    dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/connectedRouteRedistRef", value=connected_route_redistribution_ref)
                )
                proposed_payload["advancedRouteMapRefs"]["connectedRouteRedistRef"] = connected_route_redistribution_ref

            if advanced_route_map_dict.get("attached_host_route_redistribution") is not None:
                attached_host_route_redistribution_ref = l3out_template_object.get_route_map(
                    "attached_host_route_redistribution",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("attached_host_route_redistribution"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(
                    dict(
                        op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/attachedHostRouteRedistRef", value=attached_host_route_redistribution_ref
                    )
                )
                proposed_payload["advancedRouteMapRefs"]["attachedHostRouteRedistRef"] = attached_host_route_redistribution_ref

            if module.params.get("inbound_route_map") is not None:
                inbound_route_map_ref = l3out_template_object.get_route_map(
                    "inbound_route_map",
                    tenant_id,
                    tenant_name,
                    module.params.get("inbound_route_map"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/importRouteMapRef", value=inbound_route_map_ref))
                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/importRouteControl", value=True if inbound_route_map_ref else False))
                proposed_payload["importRouteMapRef"] = inbound_route_map_ref
                proposed_payload["importRouteControl"] = True if inbound_route_map_ref else False

            if module.params.get("outbound_route_map") is not None:
                outbound_route_map_ref = l3out_template_object.get_route_map(
                    "outbound_route_map",
                    tenant_id,
                    tenant_name,
                    module.params.get("outbound_route_map"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/exportRouteMapRef", value=outbound_route_map_ref))
                proposed_payload["exportRouteMapRef"] = outbound_route_map_ref

            if advanced_route_map_dict.get("route_dampening_ipv4") is not None:
                route_dampening_ipv4_ref = l3out_template_object.get_route_map(
                    "route_dampening_ipv4",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("route_dampening_ipv4"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/routeDampeningV4Ref", value=route_dampening_ipv4_ref))
                proposed_payload["advancedRouteMapRefs"]["routeDampeningV4Ref"] = route_dampening_ipv4_ref

            if advanced_route_map_dict.get("route_dampening_ipv6") is not None:
                route_dampening_ipv6_ref = l3out_template_object.get_route_map(
                    "route_dampening_ipv6",
                    tenant_id,
                    tenant_name,
                    advanced_route_map_dict.get("route_dampening_ipv6"),
                    route_map_objects,
                ).get("uuid", "")

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/advancedRouteMapRefs/routeDampeningV6Ref", value=route_dampening_ipv6_ref))
                proposed_payload["advancedRouteMapRefs"]["routeDampeningV6Ref"] = route_dampening_ipv6_ref

            if originate_default_route is not None and originate_default_route != "":
                if not mso.existing.get("defaultRouteLeak"):
                    update_ops.append(dict(op="replace", path=l3out_attrs_path + "/defaultRouteLeak", value=dict()))
                    proposed_payload["defaultRouteLeak"] = dict()

                update_ops.append(dict(op="replace", path=l3out_attrs_path + "/defaultRouteLeak/originateDefaultRoute", value=originate_default_route))
                proposed_payload["defaultRouteLeak"]["originateDefaultRoute"] = originate_default_route

                if originate_default_route_always is not None:
                    update_ops.append(dict(op="replace", path=l3out_attrs_path + "/defaultRouteLeak/always", value=originate_default_route_always))
                    proposed_payload["defaultRouteLeak"]["always"] = originate_default_route_always

            elif mso.existing.get("defaultRouteLeak") and originate_default_route == "":
                update_ops.append(dict(op="remove", path=l3out_attrs_path + "/defaultRouteLeak"))
                del proposed_payload["defaultRouteLeak"]
                del mso.existing["defaultRouteLeak"]

            if routing_protocols in (["ospf"], ["bgp", "ospf"]):
                if ospf_area_config_dict:
                    if not mso.existing.get("ospfAreaConfig"):
                        update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig", value=dict()))
                        proposed_payload["ospfAreaConfig"] = dict()

                    update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/cost", value=ospf_area_config_dict.get("ospf_cost")))
                    update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/id", value=ospf_area_config_dict.get("ospf_area_id")))
                    update_ops.append(
                        dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/areaType", value=ospf_area_config_dict.get("ospf_area_type"))
                    )

                    proposed_payload["ospfAreaConfig"]["cost"] = ospf_area_config_dict.get("ospf_cost")
                    proposed_payload["ospfAreaConfig"]["id"] = ospf_area_config_dict.get("ospf_area_id")
                    proposed_payload["ospfAreaConfig"]["areaType"] = ospf_area_config_dict.get("ospf_area_type")

                    redistribute = ospf_area_config_dict.get("send_redistributed_lsas")
                    originate = ospf_area_config_dict.get("originate_summary_lsa")
                    suppress_fa = ospf_area_config_dict.get("suppress_forwarding_addr_translated_lsa")

                    if (redistribute is not None or originate is not None or suppress_fa is not None) and not mso.existing.get("ospfAreaConfig", {}).get(
                        "control"
                    ):
                        update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/control", value=dict()))
                        proposed_payload["ospfAreaConfig"]["control"] = dict()

                    if redistribute is not None:
                        update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/control/redistribute", value=redistribute))
                        proposed_payload["ospfAreaConfig"]["control"]["redistribute"] = redistribute

                    if originate is not None:
                        update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/control/originate", value=originate))
                        proposed_payload["ospfAreaConfig"]["control"]["originate"] = originate

                    if suppress_fa is not None:
                        update_ops.append(dict(op="replace", path=l3out_attrs_path + "/ospfAreaConfig/control/suppressFA", value=suppress_fa))
                        proposed_payload["ospfAreaConfig"]["control"]["suppressFA"] = suppress_fa

            elif routing_protocols not in (["ospf"], ["bgp", "ospf"]) and mso.existing.get("ospfAreaConfig") and ospf_area_config_dict == {}:
                update_ops.append(dict(op="remove", path=l3out_attrs_path + "/ospfAreaConfig"))
                del proposed_payload["ospfAreaConfig"]
                del mso.existing["ospfAreaConfig"]

            mso.sanitize(proposed_payload, collate=True)
            ops = update_ops

        mso.existing = mso.proposed

    elif state == "absent":
        if mso.existing:
            ops = [dict(op="remove", path="/l3outTemplate/l3outs/{0}".format(l3out_object_index))]
        mso.existing = {}

    if not module.check_mode and ops:
        l3out_template_path = "{0}/{1}".format(l3out_template_object.templates_path, l3out_template_object.template_id)
        mso.request(l3out_template_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
