#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
module: ndo_l3out_bgp_peer
short_description: Manage L3Out BGP Peer on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out BGP Peer on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the L3Out template.
    type: str
    aliases: [ l3out_template ]
  template_id:
    description:
    - The ID of the L3Out template.
    type: str
    aliases: [ l3out_template_id ]
  l3out:
    description:
    - The name of the L3Out.
    type: str
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    type: str
  node_group:
    description:
    - The name of the Node Group Policy.
    type: str
    required: true
  ipv4_address:
    description:
    - The IPv4 address of the L3Out BGP Peer.
    - Providing an empty string will remove the O(ipv4_address="") from the L3Out BGP Peer.
    type: str
    aliases: [ peer_address_ipv4 ]
  ipv6_address:
    description:
    - The IPv6 address of the L3Out BGP Peer.
    - Providing an empty string will remove the O(ipv6_address="") from the L3Out BGP Peer.
    type: str
    aliases: [ peer_address_ipv6 ]
  remote_asn:
    description:
    - The remote autonomous system number (ASN) of the L3Out BGP Peer.
    - The value must be between 1 and 4294967295.
    type: int
  admin_state:
    description:
    - The administrative state of the L3Out BGP Peer.
    - Defaults to C(enabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  auth_password:
    description:
    - The authentication password of the L3Out BGP Peer.
    type: str
  ebgp_multi_hop_ttl:
    description:
    - The TTL for eBGP multi-hop of the L3Out BGP Peer.
    - Defaults to 1 when unset during creation.
    - The value must be between 1 and 255.
    type: int
  site_of_origin:
    description:
    - The site of origin for the L3Out BGP Peer. The value must adhere to the pattern "extended:as2-nn2:1000:65534".
    type: str
    aliases: [ fabric_of_origin ]
  weight:
    description:
    - The weight of the L3Out BGP Peer.
    - The value must be between 1 and 65535.
    type: int
  allowed_self_as_count:
    description:
    - The allowed self-AS count of the L3Out BGP Peer.
    - Defaults to 3 when unset during creation.
    - The value must be between 1 and 10.
    type: int
  local_asn_config:
    description:
    - The configuration for local ASN of the L3Out BGP Peer.
    type: str
    choices: [ none, no_prepend, dual_as, replace_as ]
  local_asn:
    description:
    - The local autonomous system number (ASN) of the L3Out BGP Peer.
    - The value must be between 1 and 4294967295.
    type: int
  import_route_map:
    description:
    - The name of the import route map.
    - Providing an empty string will remove the O(import_route_map="") from the L3Out BGP Peer.
    type: str
  import_route_map_uuid:
    description:
    - The UUID of the import route map.
    - Providing an empty string will remove the O(import_route_map_uuid="") from the L3Out BGP Peer.
    type: str
  export_route_map:
    description:
    - The name of the export route map.
    - Providing an empty string will remove the O(export_route_map="") from the L3Out BGP Peer.
    type: str
  export_route_map_uuid:
    description:
    - The UUID of the export route map.
    - Providing an empty string will remove the O(export_route_map_uuid="") from the L3Out BGP Peer.
    type: str
  peer_prefix:
    description:
    - The name of the peer prefix.
    - Providing an empty string will remove the O(peer_prefix="") from the L3Out BGP Peer.
    type: str
  peer_prefix_uuid:
    description:
    - The UUID of the peer prefix.
    - Providing an empty string will remove the O(peer_prefix_uuid="") from the L3Out BGP Peer.
    type: str
  bgp_controls:
    description:
    - The BGP control settings for the peer.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BGP control settings.
        - Use C(disabled) to remove the BGP control settings.
        type: str
        choices: [ enabled, disabled ]
      allow_self_as:
        description:
        - The allow self AS flag of the BGP control.
        type: bool
      override_as:
        description:
        - The override AS flag of the BGP control.
        type: bool
      disabled_peer_as_check:
        description:
        - The disable peer AS check flag of the BGP control.
        type: bool
      next_hop_self:
        description:
        - The set next hop to self flag of the BGP control.
        type: bool
      send_community:
        description:
        - The send community flag of the BGP control.
        type: bool
      send_extended_community:
        description:
        - The send extended community flag of the BGP control.
        type: bool
      send_domain_path:
        description:
        - The send domain path flag of the BGP control.
        type: bool
  peer_controls:
    description:
    - The Peer control settings for the BGP peer.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the Peer control settings.
        - Use C(disabled) to remove the Peer control settings.
        type: str
        choices: [ enabled, disabled ]
      bfd:
        description:
        - The Enable Bidirectional Forwarding Detection (BFD) flag of the Peer control.
        type: bool
      disable_peer_connected_check:
        description:
        - The disable peer connected check flag of the Peer control.
        type: bool
  address_families:
    description:
    - The address family controls for the BGP peer.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the address control settings.
        - Use C(disabled) to remove the address control settings.
        type: str
        choices: [ enabled, disabled ]
      multicast:
        description:
        - The multicast address flag of the address family.
        type: bool
      unicast:
        description:
        - The unicast address flag of the address family.
        type: bool
  private_as_controls:
    description:
    - The private AS control settings for the BGP peer.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the private AS control settings.
        - Use C(disabled) to remove the private AS control settings.
        type: str
        choices: [ enabled, disabled ]
      remove_all:
        description:
        - The remove all flag of the private AS numbers.
        type: bool
      replace_with_local_as:
        description:
        - The replace private AS with local AS flag of the private AS control.
        type: bool
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
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out.
- The O(node_group) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_node_group_policy) to create the L3Out Node Group Policy.
- The O(peer_prefix) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_tenant_bgp_peer_prefix_policy) to create the BGP Peer Prefix Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_node_group_policy
- module: cisco.mso.ndo_tenant_bgp_peer_prefix_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an L3Out BGP Peer with minimum configuration
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    ipv6_address: "1::8/16"
    auth_password: 123
    state: present

- name: Update an L3Out BGP Peer with full configuration
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    ipv6_address: "1::8/16"
    remote_asn: 2
    admin_state: enabled
    import_route_map: ans_route_map
    export_route_map: ans_route_map_2
    peer_prefix: ansible_test_bgp_peer_prefix_policy
    ebgp_multi_hop_ttl: 1
    auth_password: 123
    weight: 2
    site_of_origin: "extended:as2-nn2:1000:65534"
    allowed_self_as_count: 3
    local_asn_config: replace_as
    local_asn: 1
    bgp_controls:
      allow_self_as: true
      override_as: true
      disabled_peer_as_check: true
      next_hop_self: true
      send_community: true
      send_extended_community: true
      send_domain_path: true
    peer_controls:
      bfd: true
      disable_peer_connected_check: true
    address_families:
      multicast: true
      unicast: true
    private_as_controls:
      remove_all: true
      replace_with_local_as: true
    state: present

- name: Query an L3Out BGP Peer with IPv4 and IPv6 addresses
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    ipv6_address: "1::8/16"
    state: query
  register: query_with_ipv4_and_ipv6

- name: Query an L3Out BGP Peer with IPv4
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    state: query
  register: query_with_ipv4

- name: Query an L3Out BGP Peer with IPv6
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv6_address: "1::8/16"
    state: query
  register: query_with_ipv6

- name: Remove an L3Out BGP Peer with IPv4 and IPv6 addresses
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    ipv6_address: "1::8/16"
    state: absent

- name: Remove an L3Out BGP Peer with IPv4
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv4_address: "1.1.1.1"
    state: absent

- name: Remove an L3Out BGP Peer with IPv6
  cisco.mso.ndo_l3out_bgp_peer:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_1
    node_group: node_group_policy_1
    ipv6_address: "1::8/16"
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import LOCAL_ASN_CONFIG
from ansible_collections.cisco.mso.plugins.module_utils.utils import (
    generate_api_endpoint,
    append_update_ops_data,
    get_template_object_name_by_uuid,
    get_object_identifier,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str"),
        l3out_uuid=dict(type="str"),
        node_group=dict(type="str", required=True),
        ipv4_address=dict(type="str", aliases=["peer_address_ipv4"]),
        ipv6_address=dict(type="str", aliases=["peer_address_ipv6"]),
        remote_asn=dict(type="int"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        import_route_map=dict(type="str"),
        export_route_map=dict(type="str"),
        peer_prefix=dict(type="str"),
        import_route_map_uuid=dict(type="str"),
        export_route_map_uuid=dict(type="str"),
        peer_prefix_uuid=dict(type="str"),
        ebgp_multi_hop_ttl=dict(type="int"),
        auth_password=dict(type="str", no_log=True),
        weight=dict(type="int"),
        site_of_origin=dict(type="str", aliases=["fabric_of_origin"]),
        allowed_self_as_count=dict(type="int"),
        local_asn_config=dict(type="str", choices=list(LOCAL_ASN_CONFIG)),
        local_asn=dict(type="int"),
        bgp_controls=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                allow_self_as=dict(type="bool"),
                override_as=dict(type="bool"),
                disabled_peer_as_check=dict(type="bool"),
                next_hop_self=dict(type="bool"),
                send_community=dict(type="bool"),
                send_extended_community=dict(type="bool"),
                send_domain_path=dict(type="bool"),
            ),
        ),
        peer_controls=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                bfd=dict(type="bool"),
                disable_peer_connected_check=dict(type="bool"),
            ),
        ),
        address_families=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                multicast=dict(type="bool"),
                unicast=dict(type="bool"),
            ),
        ),
        private_as_controls=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                remove_all=dict(type="bool"),
                replace_with_local_as=dict(type="bool"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["template", "template_id"], True],
            ["state", "query", ["template", "template_id"], True],
            ["state", "absent", ["template", "template_id"], True],
            ["state", "present", ["l3out", "l3out_uuid"], True],
            ["state", "query", ["l3out", "l3out_uuid"], True],
            ["state", "absent", ["l3out", "l3out_uuid"], True],
            ["state", "present", ["ipv4_address", "ipv6_address"], True],
            ["state", "absent", ["ipv4_address", "ipv6_address"], True],
        ],
        mutually_exclusive=[
            ("template", "template_id"),
            ("l3out", "l3out_uuid"),
            ("import_route_map", "import_route_map_uuid"),
            ("export_route_map", "export_route_map_uuid"),
            ("peer_prefix", "peer_prefix_uuid"),
        ],
    )

    mso = MSOModule(module)

    template_identifier = get_object_identifier(module.params.get("template_id"), module.params.get("template"))
    template_identifier["id"] = template_identifier.get("uuid")
    l3out_identifier = get_object_identifier(module.params.get("l3out_uuid"), module.params.get("l3out"))
    node_group = module.params.get("node_group")
    ipv4_addr = module.params.get("ipv4_address")
    ipv6_addr = module.params.get("ipv6_address")
    remote_asn = module.params.get("remote_asn")
    admin_state = module.params.get("admin_state")
    auth_password = module.params.get("auth_password")
    ebgp_multi_hop_ttl = module.params.get("ebgp_multi_hop_ttl")
    site_of_origin = module.params.get("site_of_origin")
    weight = module.params.get("weight")
    allowed_self_as_count = module.params.get("allowed_self_as_count")
    local_asn_config = LOCAL_ASN_CONFIG.get(module.params.get("local_asn_config"))
    local_asn = module.params.get("local_asn")

    import_route_map_identifier = get_object_identifier(module.params.get("import_route_map_uuid"), module.params.get("import_route_map"))
    export_route_map_identifier = get_object_identifier(module.params.get("export_route_map_uuid"), module.params.get("export_route_map"))
    peer_prefix_identifier = get_object_identifier(module.params.get("peer_prefix_uuid"), module.params.get("peer_prefix"))

    bgp_controls = module.params.get("bgp_controls")
    peer_controls = module.params.get("peer_controls")
    address_families = module.params.get("address_families")
    private_as_controls = module.params.get("private_as_controls")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "l3out", template_identifier.get("name"), template_identifier.get("id"))
    mso_template.validate_template("l3out")

    tenant_id = mso_template.template_summary.get("tenantId")
    tenant_name = mso_template.template_summary.get("tenantName")

    l3out_object = mso_template.get_l3out_object(uuid=l3out_identifier.get("uuid"), name=l3out_identifier.get("name"), fail_module=True)
    node_group_object = mso_template.get_l3out_node_group(node_group, l3out_object.details, fail_module=True)

    bgp_peer_objects = get_bgp_peer_by_address(mso_template, node_group_object.details.get("bgpPeers", []), ipv4_addr=ipv4_addr, ipv6_addr=ipv6_addr)

    if bgp_peer_objects and (ipv4_addr or ipv6_addr):
        set_bgp_peer_relations_name(mso, bgp_peer_objects.details)
        mso.existing = mso.previous = copy.deepcopy(bgp_peer_objects.details)  # Query a specific object
    elif bgp_peer_objects:
        mso.existing = [set_bgp_peer_relations_name(mso, bgp_peer) for bgp_peer in bgp_peer_objects]  # Query all objects

    if state != "query":
        bgp_peer_path = "/l3outTemplate/l3outs/{0}/nodeGroups/{1}/bgpPeers/{2}".format(
            l3out_object.index, node_group_object.index, bgp_peer_objects.index if bgp_peer_objects else "-"
        )

    ops = []

    if state == "present":
        peer_prefix_uuid = None

        if peer_prefix_identifier.get("uuid") is not None:
            peer_prefix_uuid = peer_prefix_identifier.get("uuid")
        elif peer_prefix_identifier.get("name") is not None and peer_prefix_identifier.get("name") != "":
            peer_prefix_uuid = mso_template.get_object_by_key_value_pairs(
                "BGP Peer Prefix Policy",
                mso.query_objs(generate_api_endpoint("templates/objects", **{"type": "bgpPeerPrefixPol", "tenant-id": tenant_id})),
                [KVPair("name", peer_prefix_identifier.get("name"))],
                True,
            ).details.get("uuid")

        route_map_objects = (
            mso.query_objs(generate_api_endpoint("templates/objects", **{"type": "routeMap", "tenant-id": tenant_id}))
            if import_route_map_identifier.get("name") or export_route_map_identifier.get("name")
            else []
        )

        import_route_map_uuid = None
        export_route_map_uuid = None

        if import_route_map_identifier.get("uuid") is not None:
            import_route_map_uuid = import_route_map_identifier.get("uuid")
        elif import_route_map_identifier.get("name") is not None:
            import_route_map_uuid = mso_template.get_route_map(
                "import_route_map",
                tenant_id,
                tenant_name,
                import_route_map_identifier.get("name"),
                route_map_objects,
            ).get("uuid", None)

        if export_route_map_identifier.get("uuid") is not None:
            export_route_map_uuid = export_route_map_identifier.get("uuid")
        elif export_route_map_identifier.get("name") is not None:
            export_route_map_uuid = mso_template.get_route_map(
                "export_route_map",
                tenant_id,
                tenant_name,
                export_route_map_identifier.get("name"),
                route_map_objects,
            ).get("uuid", None)

        mso_values = dict(
            peerAddressV4=ipv4_addr,
            peerAddressV6=ipv6_addr,
            peerAsn=remote_asn,
            adminState=admin_state,
            authEnabled=True if auth_password else False,
            allowedSelfASCount=allowed_self_as_count,
            ebpgMultiHopTTL=ebgp_multi_hop_ttl,
            weight=weight,
            siteOfOrigin=site_of_origin,
            localAsnConfig=local_asn_config,
            localAsn=local_asn,
            peerPrefixRef=peer_prefix_uuid,
            importRouteMapRef=import_route_map_uuid,
            exportRouteMapRef=export_route_map_uuid,
            password=dict(value=auth_password) if auth_password is not None else None,
        )

        if not mso.existing:
            # BGP Controls
            if bgp_controls:
                mso_values["bgpControls"] = dict(
                    allowSelfAS=bgp_controls["allow_self_as"],
                    asOverride=bgp_controls["override_as"],
                    disablePeerASCheck=bgp_controls["disabled_peer_as_check"],
                    nextHopSelf=bgp_controls["next_hop_self"],
                    sendCommunity=bgp_controls["send_community"],
                    sendDomainPath=bgp_controls["send_extended_community"],
                    sendExtendedCommunity=bgp_controls["send_domain_path"],
                )

            # Peer Controls
            if peer_controls:
                mso_values["peerControls"] = dict(bfd=peer_controls["bfd"], disableConnectedCheck=peer_controls["disable_peer_connected_check"])

            # Address Type Controls
            if address_families:
                mso_values["addressTypeControls"] = dict(afMast=address_families["multicast"], afUcast=address_families["unicast"])

            # Private AS Controls
            if private_as_controls:
                mso_values["privateASControls"] = dict(
                    removeAll=private_as_controls["remove_all"], replaceWithLocalAS=private_as_controls["replace_with_local_as"]
                )

            if private_as_controls and (private_as_controls.get("remove_all") or private_as_controls.get("replace_with_local_as")):
                mso_values["privateASControls"]["removeExclusive"] = True

            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=bgp_peer_path, value=mso.sent))

        elif mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)
            mso_values_remove = list()

            if ipv4_addr == "" and "peerAddressV4" in proposed_payload:
                mso_values_remove.append("peerAddressV4")
                mso_values.pop("peerAddressV4", None)

            if ipv6_addr == "" and "peerAddressV6" in proposed_payload:
                mso_values_remove.append("peerAddressV6")
                mso_values.pop("peerAddressV6", None)

            if remote_asn == 0 and "peerAsn" in proposed_payload:
                mso_values_remove.append("peerAsn")
                mso_values.pop("peerAsn", None)

            if weight == 0 and "weight" in proposed_payload:
                mso_values_remove.append("weight")
                mso_values.pop("weight", None)

            if site_of_origin == "" and "siteOfOrigin" in proposed_payload:
                mso_values_remove.append("siteOfOrigin")
                mso_values.pop("siteOfOrigin", None)

            if local_asn == 0 and "localAsn" in proposed_payload:
                mso_values_remove.append("localAsn")
                mso_values.pop("localAsn", None)

            if mso.existing.get("password", {}).get("ref"):
                mso.existing["password"].pop("ref", None)
                mso.previous["password"].pop("ref", None)

            if auth_password == "" and "password" in proposed_payload:
                mso_values["authEnabled"] = False
                mso_values.pop("password", None)
                mso_values_remove.append("password")
            elif auth_password == "" and "password" in mso_values and "password" not in proposed_payload:
                mso_values.pop("password", None)

            if (peer_prefix_identifier.get("uuid") == "" or peer_prefix_identifier.get("name") == "") and "peerPrefixRef" in proposed_payload:
                mso_values_remove.append("peerPrefixRef")
                mso_values.pop("peerPrefixRef", None)

            if (import_route_map_identifier.get("uuid") == "" or import_route_map_identifier.get("name") == "") and "importRouteMapRef" in proposed_payload:
                mso_values_remove.append("importRouteMapRef")
                mso_values.pop("importRouteMapRef", None)

            if (export_route_map_identifier.get("uuid") == "" or export_route_map_identifier.get("name") == "") and "exportRouteMapRef" in proposed_payload:
                mso_values_remove.append("exportRouteMapRef")
                mso_values.pop("exportRouteMapRef", None)

            # BGP Controls
            if bgp_controls is not None:
                if bgp_controls.get("state") == "disabled" and proposed_payload.get("bgpControls"):
                    mso_values_remove.append("bgpControls")
                    mso_values.pop("bgpControls", None)
                elif bgp_controls.get("state") != "disabled":
                    if not proposed_payload.get("bgpControls"):
                        mso_values["bgpControls"] = dict()
                    mso_values[("bgpControls", "allowSelfAS")] = bgp_controls.get("allow_self_as")
                    mso_values[("bgpControls", "asOverride")] = bgp_controls.get("override_as")
                    mso_values[("bgpControls", "disablePeerASCheck")] = bgp_controls.get("disabled_peer_as_check")
                    mso_values[("bgpControls", "nextHopSelf")] = bgp_controls.get("next_hop_self")
                    mso_values[("bgpControls", "sendCommunity")] = bgp_controls.get("send_community")
                    mso_values[("bgpControls", "sendExtendedCommunity")] = bgp_controls.get("send_extended_community")
                    mso_values[("bgpControls", "sendDomainPath")] = bgp_controls.get("send_domain_path")

            # Peer Controls
            if peer_controls is not None:
                if peer_controls.get("state") == "disabled" and proposed_payload.get("peerControls"):
                    mso_values_remove.append("peerControls")
                    mso_values.pop("peerControls", None)
                elif peer_controls.get("state") != "disabled":
                    if not proposed_payload.get("peerControls"):
                        mso_values["peerControls"] = dict()

                    mso_values[("peerControls", "bfd")] = peer_controls.get("bfd")
                    mso_values[("peerControls", "disableConnectedCheck")] = peer_controls.get("disable_peer_connected_check")

            # Address Type Controls
            if address_families is not None:
                if address_families.get("state") == "disabled" and proposed_payload.get("addressTypeControls"):
                    mso_values_remove.append("addressTypeControls")
                    mso_values.pop("addressTypeControls", None)
                elif address_families.get("state") != "disabled":
                    if not proposed_payload.get("addressTypeControls"):
                        mso_values["addressTypeControls"] = dict()

                    mso_values[("addressTypeControls", "afMast")] = address_families.get("multicast")
                    mso_values[("addressTypeControls", "afUcast")] = address_families.get("unicast")

            # Private AS Controls
            if private_as_controls is not None:
                if private_as_controls.get("state") == "disabled" and proposed_payload.get("privateASControls"):
                    mso_values_remove.append("privateASControls")
                    mso_values.pop("privateASControls", None)
                elif private_as_controls.get("state") != "disabled":
                    if not proposed_payload.get("privateASControls"):
                        mso_values["privateASControls"] = dict()

                    mso_values[("privateASControls", "removeAll")] = private_as_controls.get("remove_all")
                    mso_values[("privateASControls", "replaceWithLocalAS")] = private_as_controls.get("replace_with_local_as")

                    if private_as_controls.get("remove_all") or private_as_controls.get("replace_with_local_as"):
                        mso_values[("privateASControls", "removeExclusive")] = True

            append_update_ops_data(ops, proposed_payload, bgp_peer_path, mso_values, mso_values_remove)
            mso.sanitize(proposed_payload)

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=bgp_peer_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_bgp_peer_by_address(
            mso_template,
            mso_template.get_l3out_node_group(
                node_group,
                mso_template.get_l3out_object(uuid=l3out_identifier.get("uuid"), name=l3out_identifier.get("name"), fail_module=True).details,
                fail_module=True,
            ).details.get("bgpPeers", []),
            ipv4_addr=ipv4_addr,
            ipv6_addr=ipv6_addr,
        )
        if match:
            if match.details.get("password", {}).get("ref"):
                match.details["password"].pop("ref", None)

            set_bgp_peer_relations_name(mso, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        set_bgp_peer_relations_name(mso, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_bgp_peer_by_address(mso_template, bgp_peers, ipv4_addr=None, ipv6_addr=None, fail_module=False):
    if bgp_peers and (ipv4_addr or ipv6_addr):  # Query a specific object
        kv_list = []
        if ipv4_addr:
            kv_list.append(KVPair("peerAddressV4", ipv4_addr))
        if ipv6_addr:
            kv_list.append(KVPair("peerAddressV6", ipv6_addr))

        return mso_template.get_object_by_key_value_pairs("L3Out BGP Peer", bgp_peers, kv_list, fail_module)
    return bgp_peers  # Query all objects


def set_bgp_peer_relations_name(mso, bgp_peer_dict):
    if bgp_peer_dict.get("exportRouteMapRef"):
        bgp_peer_dict["exportRouteMapName"] = get_template_object_name_by_uuid(mso, "routeMap", bgp_peer_dict.get("exportRouteMapRef"))

    if bgp_peer_dict.get("importRouteMapRef"):
        bgp_peer_dict["importRouteMapName"] = get_template_object_name_by_uuid(mso, "routeMap", bgp_peer_dict.get("importRouteMapRef"))

    if bgp_peer_dict.get("peerPrefixRef"):
        bgp_peer_dict["peerPrefixName"] = get_template_object_name_by_uuid(mso, "bgpPeerPrefixPol", bgp_peer_dict.get("peerPrefixRef"))

    return bgp_peer_dict


if __name__ == "__main__":
    main()
