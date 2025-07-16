# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.constants import TEMPLATE_TYPES
from ansible_collections.cisco.mso.plugins.module_utils.utils import generate_api_endpoint
from collections import namedtuple

KVPair = namedtuple("KVPair", "key value")
Item = namedtuple("Item", "index details")
SearchQuery = namedtuple("SearchQuery", "key kv_pairs")


class MSOTemplate:
    def __init__(self, mso_module, template_type=None, template_name=None, template_id=None, schema_name=None, schema_id=None, fail_module=False):
        self.mso = mso_module
        self.templates_path = "templates"
        self.summaries_path = "{0}/summaries".format(self.templates_path)
        self.template = {}
        self.template_path = ""
        self.template_name = template_name
        self.template_id = template_id
        self.template_type = template_type
        self.template_summary = {}
        self.template_objects_cache = {}
        self.schema_path = None
        self.schema_name = schema_name
        self.schema_id = schema_id

        if template_id:
            # Checking if the template with id exists to avoid error: MSO Error 400: Template ID 665da24b95400f375928f195 invalid
            self.template_summary = self.mso.get_obj(self.summaries_path, templateId=self.template_id)
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_id)
                self.template = self.mso.query_obj(self.template_path)
                self.template_name = self.template.get("displayName")
                self.template_type = self.template.get("templateType")
                if template_type == "application":
                    self._set_schema_properties()
            else:
                self.mso.fail_json(
                    msg="Provided template id '{0}' does not exist. Existing templates: {1}".format(
                        self.template_id,
                        [
                            "Template '{0}' with id '{1}'".format(template.get("templateName"), template.get("templateId"))
                            for template in self.mso.query_objs(self.summaries_path)
                        ],
                    )
                )
        elif template_name:
            if not template_type:
                self.mso.fail_json(msg="Template type must be provided when using template name.")
            self.template_summary = self.mso.get_obj(
                self.summaries_path,
                templateName=self.template_name,
                templateType=TEMPLATE_TYPES[template_type]["template_type"],
                schemaName=self.schema_name,
                schemaId=self.schema_id,
            )
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_summary.get("templateId"))
                self.template = self.mso.query_obj(self.template_path)
                self.template_id = self.template.get("templateId")
                self.template_type = self.template.get("templateType")
                if template_type == "application":
                    self._set_schema_properties()

            if fail_module and not self.template:
                self.mso.fail_json(
                    msg="Provided template name '{0}' does not exist. Existing templates: {1}".format(
                        self.template_name,
                        [
                            "Template '{0}' with id '{1}'".format(template.get("templateName"), template.get("templateId"))
                            for template in self.mso.query_objs(self.summaries_path, templateType=TEMPLATE_TYPES[template_type]["template_type"])
                        ],
                    )
                )

        elif template_type:
            self.template = self.mso.query_objs(self.summaries_path, templateType=TEMPLATE_TYPES[template_type]["template_type"])
        else:
            self.template = self.mso.query_objs(self.summaries_path)

        # Remove unwanted keys from existing object for better output and diff compares
        if isinstance(self.template, dict):
            for key in ["_updateVersion", "version"]:
                self.template.pop(key, None)

    def _set_schema_properties(self):
        self.schema_name = self.template_summary.get("schemaName")
        self.schema_id = self.template_summary.get("schemaId")
        self.schema_path = "schemas/{0}".format(self.schema_id)

    @staticmethod
    def get_object_from_list(search_list, kv_list):
        """
        Get the first matched object from a list of mso object dictionaries.
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :return: The index and details of the object. -> Item (Named Tuple)
                 Values of provided keys of all existing objects. -> List
        """

        # Sometimes the attribute returned by api might be None
        # If search_list is None, iterating over it will throw an error
        # Thus we need to return the match of None and without existing values
        if search_list is None:
            return None, []

        def kv_match(kvs, item):
            return all((item.get(kv.key) == kv.value for kv in kvs))

        match = next((Item(index, item) for index, item in enumerate(search_list) if kv_match(kv_list, item)), None)
        existing = [item.get(kv.key) for item in search_list for kv in kv_list]
        return match, existing

    def validate_template(self, template_type):
        """
        Validate that attributes are set to a value that is not equal None.
        :return: None
        """
        if not self.template or not isinstance(self.template, dict):
            self.mso.fail_json(msg="Template '{0}' not found.".format(self.template_name))
        if self.template.get("templateType") != template_type:
            self.mso.fail_json(msg="Template type must be '{0}'.".format(template_type))

    def get_object_by_key_value_pairs(self, object_description, search_list, kv_list, fail_module=False):
        """
        Get the object from a list of mso object dictionaries by name.
        :param object_description: Description of the object to search for -> Str
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: The object. -> Dict | None
        """
        match, existing = self.get_object_from_list(search_list, kv_list)
        if not match and fail_module:
            msg = "Provided {0} with '{1}' not matching existing object(s): {2}".format(object_description, kv_list, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        return match

    def get_object_by_uuid(self, object_description, search_list, uuid, fail_module=False):
        """
        Get the object from a list of mso object dictionaries by uuid.
        :param object_description: Description of the object to search for -> Str
        :param search_list: Objects to search through -> List.
        :param uuid: UUID of the object to search for -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: The object. -> Dict | None
        """
        kv_list = [KVPair("uuid", uuid)]
        return self.get_object_by_key_value_pairs(object_description, search_list, kv_list, fail_module)

    def get_vlan_pool_uuid(self, vlan_pool_name):
        """
        Get the UUID of a VLAN pool by name.
        :param vlan_pool_name: Name of the VLAN pool to search for -> Str
        :return: UUID of the VLAN pool. -> Str
        """
        existing_vlan_pools = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("vlanPools", [])
        kv_list = [KVPair("name", vlan_pool_name)]
        match = self.get_object_by_key_value_pairs("VLAN Pool", existing_vlan_pools, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_vlan_pool_name(self, vlan_pool_uuid):
        """
        Get the UUID of a VLAN pool by name.
        :param vlan_pool_name: Name of the VLAN pool to search for -> Str
        :return: UUID of the VLAN pool. -> Str
        """
        existing_vlan_pools = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("vlanPools", [])
        kv_list = [KVPair("uuid", vlan_pool_uuid)]
        match = self.get_object_by_key_value_pairs("VLAN Pool", existing_vlan_pools, kv_list, fail_module=True)
        return match.details.get("name")

    def get_route_map(self, attr_name, tenant_id, tenant_name, route_map, route_map_objects):
        """
        Retrieves the details of a specific route map object based on the provided attributes.
        :param attr_name: The attribute name for error messaging. -> Str
        :param tenant_id: The ID of the tenant. -> Str
        :param tenant_name: The name of the tenant. -> Str
        :param route_map: The name of the route map. -> Str
        :param route_map_objects: The list of route map objects to search from. -> List
        :return: The details of the route map object if found, otherwise an empty dictionary. -> Dict
        """
        if route_map and tenant_id and route_map_objects:
            route_map_object = self.get_object_from_list(
                route_map_objects,
                [KVPair("name", route_map), KVPair("tenantId", tenant_id)],
            )
            if route_map_object[0]:
                return route_map_object[0].details
            else:
                self.mso.fail_json(msg="Provided Route Map {0}: {1} with the tenant: {2} not found.".format(attr_name, route_map, tenant_name))
        else:
            return {}

    def get_vrf_object(self, vrf_dict, tenant_id, templates_objects_path):
        """
        Get VRF object based on provided parameters.
        :param vrf_dict: Dictionary containing VRF details. -> Dict
        :param tenant_id: Id of the tenant. -> Str
        :param templates_objects_path: Path to the templates objects. -> Str
        :return: VRF object if found, otherwise fail with an error message. -> Dict
        """

        vrf_path = generate_api_endpoint(templates_objects_path, **{"type": "vrf", "tenant-id": tenant_id, "include-common": "true"})
        vrf_objects = self.mso.query_objs(vrf_path)
        vrf_kv_list = [
            KVPair("name", vrf_dict.get("name")),
            KVPair("templateName", vrf_dict.get("template")),
            KVPair("schemaName", vrf_dict.get("schema")),
            KVPair("tenantId", tenant_id),
        ]

        vrf_object = self.get_object_from_list(vrf_objects, vrf_kv_list)

        if vrf_object[0]:
            return vrf_object[0]
        else:
            self.mso.fail_json(msg="Provided VRF {0} not found.".format(vrf_dict.get("name")))

    def get_l3out_node_routing_policy_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the L3Out Node Routing Policy by UUID or Name.
        :param uuid: UUID of the L3Out Node Routing Policy to search for -> Str
        :param name: Name of the L3Out Node Routing Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_l3out_node_routing_policy = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("l3OutNodePolGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Node Routing Policy", existing_l3out_node_routing_policy, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return existing_l3out_node_routing_policy  # Query all objects

    def get_interface_policy_group_uuid(self, interface_policy_group):
        """
        Get the UUID of an Interface Policy Group by name.
        :param interface_policy_group: Name of the Interface Policy Group to search for -> Str
        :return: UUID of the Interface Policy Group. -> Str
        """
        existing_policy_groups = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("interfacePolicyGroups", [])
        kv_list = [KVPair("name", interface_policy_group)]
        match = self.get_object_by_key_value_pairs("Interface Policy Groups", existing_policy_groups, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_ipsla_monitoring_policy(self, uuid=None, name=None, fail_module=False):
        """
        Get the IPSLA Monitoring Policy by UUID or Name.
        :param uuid: UUID of the IPSLA Monitoring Policy to search for -> Str
        :param name: Name of the IPSLA Monitoring Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_ipsla_policies = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaMonitoringPolicies", [])
        if name or uuid:
            return self.get_object_by_key_value_pairs(
                "IPSLA Monitoring Policy",
                existing_ipsla_policies,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module=fail_module,
            )
        return existing_ipsla_policies

    def get_l3out_object(self, uuid=None, name=None, fail_module=False, search_object=None):
        """
        Get the L3Out by uuid or name.
        :param uuid: UUID of the L3Out to search for -> Str
        :param name: Name of the L3Out to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_l3outs = search_object.get("l3outTemplate", {}).get("l3outs", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out", existing_l3outs, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_l3outs  # Query all objects

    def get_l3out_node_group(self, name, l3out_object, fail_module=False):
        """
        Get the L3Out Node Group Policy by name.
        :param name: Name of the L3Out Node Group Policy to search for -> Str
        :param l3out_object: L3Out object to search Node Group Policy -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the Name is existing in the search list -> Dict
                 When the Name is not existing in the search list -> None
                 When the Name is None, and the search list is not empty -> List[Dict]
                 When the Name is None, and the search list is empty -> List[]
        """
        existing_l3out_node_groups = l3out_object.get("nodeGroups", [])
        if name:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node Group Policy", existing_l3out_node_groups, [KVPair("name", name)], fail_module)
        return existing_l3out_node_groups  # Query all objects

    def get_port_channel(self, uuid=None, name=None, fail_module=False):
        """
        Get the port channel by uuid or name.
        :param uuid: UUID of the Port Channel to search for -> Str
        :param name: Name of the Port Channel to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_port_channels = self.template.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Port Channel", existing_port_channels, [KVPair("uuid", uuid)] if uuid else [KVPair("name", name)], fail_module=fail_module
            )
        return existing_port_channels

    def get_l3out_node(self, l3out_object, pod_id, node_id, fail_module=False):
        """
        Get the L3Out Node by pod_id and node_id.
        :param l3out_object: L3Out object to search for the Node -> Dict
        :param pod_id: Pod ID of the Node to search for -> Str
        :param node_id: Node ID of the Node to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id | node_id is existing in the search list -> Dict
                 When the pod_id | node_id is not existing in the search list -> None
                 When both pod_id and node_id are None, and the search list is not empty -> List[Dict]
                 When both pod_id and node_id are None, and the search list is empty -> List[]
        """
        existing_l3out_nodes = l3out_object.get("nodes", [])
        if pod_id and node_id:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node", existing_l3out_nodes, [KVPair("podID", pod_id), KVPair("nodeID", node_id)], fail_module)
        return existing_l3out_nodes  # Query all objects

    def get_l3out_node_static_route(self, node_object, prefix, fail_module=False):
        """
        Get the L3Out Node Static Route by prefix.
        :param node_object: L3Out Node object to search for the Static Route -> Dict
        :param prefix: Prefix of the Static Route to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the prefix is existing in the search list -> Dict
                 When the prefix is not existing in the search list -> None
                 When the prefix is None, and the search list is not empty -> List[Dict]
                 When the prefix is None, and the search list is empty -> List[]
        """
        existing_l3out_static_routes = node_object.get("staticRoutes", [])
        if prefix:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node Static Route", existing_l3out_static_routes, [KVPair("prefix", prefix)], fail_module)
        return existing_l3out_static_routes  # Query all objects

    def get_l3out_node_static_route_next_hop(self, static_route_object, ip, fail_module=False):
        """
        Get the L3Out Node Static Route Next Hop by IP.
        :param static_route_object: L3Out Node Static Route object to search for the Next Hop -> Dict
        :param ip: IP of the Static Route Next Hop to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the IP is existing in the search list -> Dict
                 When the IP is not existing in the search list -> None
                 When the IP is None, and the search list is not empty -> List[Dict]
                 When the IP is None, and the search list is empty -> List[]
        """
        existing_l3out_static_route_next_hops = static_route_object.get("nextHops", [])
        if ip:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Node Static Route Next Hop", existing_l3out_static_route_next_hops, [KVPair("nextHopIP", ip)], fail_module
            )
        return existing_l3out_static_route_next_hops  # Query all objects

    def get_ipsla_track_list(self, uuid=None, name=None, fail_module=False):
        """
        Get the IPSLA Track List by uuid or name.
        :param uuid: UUID of the IPSLA Track List to search for -> Str
        :param name: Name of the IPSLA Track List to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_ipsla_track_lists = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaTrackLists", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "IPSLA Track List",
                existing_ipsla_track_lists,
                [KVPair("uuid", uuid)] if uuid else [KVPair("name", name)],
                fail_module=fail_module,
            )
        return existing_ipsla_track_lists  # Query all objects

    def get_l3out_routed_interface(self, l3out_object, pod_id, node_id, path, path_ref, fail_module=False):
        """
        Get the L3Out Routed Interface by pod_id, node_id, path, and path_ref.
        :param l3out_object: L3Out object to search for the Routed Interface -> Dict
        :param pod_id: Pod ID of the Routed Interface to search for -> Str
        :param node_id: Node ID of the Routed Interface to search for -> Str
        :param path: Path of the Routed Interface to search for -> Str
        :param path_ref: Path reference of the Routed Interface to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id, path | path_ref is existing in the search list -> Dict
                 When the pod_id, node_id, path | path_ref is not existing in the search list -> None
                 When both pod_id, node_id, path and path_ref are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, path and path_ref are None, and the search list is empty -> List[]
        """
        existing_l3out_interfaces = l3out_object.get("interfaces", [])
        if (pod_id and node_id and path) or path_ref:  # Query a specific object
            if path_ref:
                kv_list = [KVPair("pathRef", path_ref)]
            else:
                kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("path", path)]

            return self.get_object_by_key_value_pairs("L3Out Interface", existing_l3out_interfaces, kv_list, fail_module)
        return existing_l3out_interfaces  # Query all objects

    def get_l3out_routed_sub_interface(self, l3out_object, pod_id, node_id, path, path_ref, encap, fail_module=False):
        """
        Get the L3Out Routed Sub-Interface by pod_id, node_id, path, and path_ref.
        :param l3out_object: L3Out object to search for the Routed Sub-Interface -> Dict
        :param pod_id: Pod ID of the Routed Sub-Interface to search for -> Str
        :param node_id: Node ID of the Routed Sub-Interface to search for -> Str
        :param path: Path of the Routed Sub-Interface to search for -> Str
        :param path_ref: Path reference of the Routed Sub-Interface to search for -> Str
        :param encap: Encapsulation details of the Routed Sub-Interface to search for -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id, path | path_ref with encap is existing in the search list -> Dict
                 When the pod_id, node_id, path | path_ref with encap is not existing in the search list -> None
                 When both pod_id, node_id, path, path_ref, and encap are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, path, path_ref, and encap are None, and the search list is empty -> List[]
        """
        existing_l3out_interfaces = l3out_object.get("subInterfaces", [])
        if ((pod_id and node_id and path) or path_ref) and encap:  # Query a specific object
            if path_ref:
                kv_list = [KVPair("pathRef", path_ref), KVPair("encap", encap)]
            else:
                kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("path", path), KVPair("encap", encap)]

            return self.get_object_by_key_value_pairs("L3Out Sub-Interface", existing_l3out_interfaces, kv_list, fail_module)
        return existing_l3out_interfaces  # Query all objects

    def get_node_settings_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the Fabric Node Settings by uuid or name.
        :param uuid: UUID of the Node Setting to search for -> Str
        :param name: Name of the Node Setting to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("nodePolicyGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Node Settings", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_pod_profile_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Pod Profile by uuid or name.
        :param uuid: UUID of the Pod Profile to search for -> Str
        :param name: Name of the Pod Profile to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricResourceTemplate", {}).get("template", {}).get("podProfiles", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Pod Profile", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_pod_settings_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Pod Settings by uuid or name.
        :param uuid: UUID of the Pod Settings to search for -> Str
        :param name: Name of the Pod Settings to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("podPolicyGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Pod Settings", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_ntp_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the NTP Policy by uuid or name.
        :param uuid: UUID of the NTP Policy to search for -> Str
        :param name: Name of the NTP Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("ntpPolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("NTP Policy", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_macsec_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the MACsec Policy by uuid or name.
        :param uuid: UUID of the MACsec Policy to search for -> Str
        :param name: Name of the MACsec Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("MACsec Policy", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_l3out_interface_routing_policy_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the L3Out Interface Routing Policy by UUID or Name.
        :param uuid: UUID of the L3Out Interface Routing Policy to search for -> Str
        :param name: Name of the L3Out Interface Routing Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_l3out_interface_routing_policy = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("l3OutIntfPolGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Interface Routing Policy",
                existing_l3out_interface_routing_policy,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module,
            )
        return existing_l3out_interface_routing_policy  # Query all objects

    def get_template_policy_uuid(self, template_type, policy_name, policy_type):
        """
        Get the UUID of a Tenant Policy by name.
        :param template_type: The type of template -> Str
        :param policy_name: Name of the policy -> Str
        :param policy_type: The type of the policy specified in the API response -> Str
        :return: UUID of the tenant policy -> Str
        """
        existing_policies = self.template.get(TEMPLATE_TYPES[template_type]["template_type_container"], {}).get("template", {}).get(policy_type, [])
        match = self.get_object_by_key_value_pairs(policy_type, existing_policies, [KVPair("name", policy_name)], fail_module=True)
        return match.details.get("uuid")

    def clear_template_objects_cache(self):
        self.template_objects_cache = {}

    def get_template_object_name_by_uuid(self, object_type, uuid, fail_module=True):
        """
        Retrieve the name of a specific object type in the MSO template using its UUID.
        :param mso: An instance of the MSO class, which provides methods for making API requests -> MSO Class instance
        :param object_type: The type of the object to retrieve the name for -> Str
        :param uuid: The UUID of the object to retrieve the name for -> Str
        :return: Str | None: The processed result which could be:
              When the UUID is existing, returns object name -> Str
              When the UUID is not existing -> None
        """
        response_object = self.get_template_object_by_uuid(object_type, uuid, fail_module)
        if response_object:
            return response_object.get("name")

    def get_template_object_by_uuid(self, object_type, uuid, fail_module=True, use_cache=False):
        """
        Retrieve a specific object type in the MSO template using its UUID.
        :param object_type: The type of the object to retrieve -> Str
        :param uuid: The UUID of the object to retrieve -> Str
        :param use_cache: Use the cached result of the templates/objects API for the UUID -> Bool
        :return: Dict | None: The processed result which could be:
            When the UUID is existing, returns object -> Dict
            When the UUID is not existing -> None
        """
        response_object = None
        if use_cache and uuid in self.template_objects_cache.keys():
            response_object = self.template_objects_cache[uuid]
        else:
            response_object = self.mso.request("templates/objects?type={0}&uuid={1}".format(object_type, uuid), "GET")
            self.template_objects_cache[uuid] = response_object
        if not response_object and fail_module:
            msg = "Provided {0} with UUID of '{1}' not found.".format(object_type, uuid)
            self.mso.fail_json(msg=msg)
        return response_object

    def update_config_with_template_and_references(self, config_data, reference_collections=None, set_template=True, use_cache=False):
        """
        Return the updated config_data with the template values and reference_collections if provided
        :param config_data: The original config_data that requires to be updated -> Dict
        :param reference_collections: A dict containing the object type, references and the corresponding names -> Dict
        :param set_template: Adds the templateId and templateName to the config_data -> Bool
        :param use_cache: Use the cached result of the templates/objects API for the ref UUID -> Bool
        :return: Updated config_data with names for references -> Dict
        Example 1:
        reference_collections = {
            "qos": {
                "name": "qosName",
                "reference": "qosRef",
                "type": "qos",
                "template": "qosTemplateName",
                "templateId": "qosTemplateId",
            },
            "interfaceRoutingPolicy": {
                "name": "interfaceRoutingPolicyName",
                "reference": "interfaceRoutingPolicyRef",
                "type": "l3OutIntfPolGroup",
                "template": "interfaceRoutingPolicyTemplateName",
                "templateId": "interfaceRoutingPolicyTemplateId",
            },
        }
        config_data = {
            "qosRef": "unique-qos-id",
            "interfaceRoutingPolicyRef": "unique-interface-id"
        }
        updated_config_data = mso_template_object.set_names_for_references(mso_instance, config_data, reference_collections)
        Expected Output:
        {    "templateName": "template_name",
             "templateId": "unique-template-id",
             "qosRef": "unique-qos-id",
             "interfaceRoutingPolicyRef": "unique-interface-id",
             "qosName": "Resolved QoS Name",
             "qosTemplateName": "Resolved QoS Template Name",
             "qosTemplateId": "Resolved QoS Template ID",
             "interfaceRoutingPolicyName": "Resolved Interface Routing Policy Name",
             "interfaceRoutingPolicyTemplateName": "Resolved Interface Routing Policy Template Name",
             "interfaceRoutingPolicyTemplateId": "Resolved Interface Routing Policy Template ID"
         }
        Example 2:
        reference_collections = {
            "stateLimitRouteMap": {
                "name": "stateLimitRouteMapName",
                "reference": "stateLimitRouteMapRef",
                "type": "mcastRouteMap"
            },
            "reportPolicyRouteMap": {
                "name": "reportPolicyRouteMapName",
                "reference": "reportPolicyRouteMapRef",
                "type": "mcastRouteMap"
            },
            "staticReportRouteMap": {
                "name": "staticReportRouteMapName",
                "reference": "staticReportRouteMapRef",
                "type": "mcastRouteMap"
            },
        }
        config_data = {
            "stateLimitRouteMapRef": "unique-state-limit-id",
            "reportPolicyRouteMapRef": "unique-report-policy-id"
        }
        updated_config_data = mso_template_object.set_names_for_references(mso_instance, config_data, reference_collections)
         Expected Output:
         {   "templateName": "template_name",
             "templateId": "unique-template-id",
             "stateLimitRouteMapRef": "unique-state-limit-id",
             "reportPolicyRouteMapRef": "unique-report-policy-id",
             "stateLimitRouteMapName": "Resolved State Limit Route Map Name",
             "reportPolicyRouteMapName": "Resolved Report Policy Route Map Name"
         }
        """

        # Set template ID and template name if available
        if set_template:
            if self.template_id:
                config_data["templateId"] = self.template_id
            if self.template_name:
                config_data["templateName"] = self.template_name
            if self.schema_id:
                config_data["schemaId"] = self.schema_id
            if self.schema_name:
                config_data["schemaName"] = self.schema_name

        # Update config data with reference names if reference_collections is provided
        if reference_collections:
            for reference_details in reference_collections.values():
                if config_data.get(reference_details.get("reference")):
                    template_object = self.get_template_object_by_uuid(
                        reference_details.get("type"), config_data.get(reference_details.get("reference")), True, use_cache
                    )
                    config_data[reference_details.get("name")] = template_object.get("name")
                    if reference_details.get("template"):
                        config_data[reference_details.get("template")] = template_object.get("templateName")
                    if reference_details.get("templateId"):
                        config_data[reference_details.get("templateId")] = template_object.get("templateId")
                    if reference_details.get("schemaId"):
                        config_data[reference_details.get("schemaId")] = template_object.get("schemaId")
                    if reference_details.get("schema"):
                        config_data[reference_details.get("schema")] = template_object.get("schemaName")
            for config_value in config_data.values():
                if isinstance(config_value, dict):
                    self.update_config_with_template_and_references(config_value, reference_collections, False, use_cache)
                elif isinstance(config_value, list):
                    for item in config_value:
                        if isinstance(item, dict):
                            self.update_config_with_template_and_references(item, reference_collections, False, use_cache)
        return config_data

    def update_config_with_port_channel_references(self, update_object):
        if update_object:
            reference_details = None
            if update_object.get("pathRef"):
                reference_details = {
                    "port_channel_reference": {
                        "name": "portChannelName",
                        "reference": "pathRef",
                        "type": "portChannel",
                        "template": "portChannelTemplateName",
                        "templateId": "portChannelTemplateId",
                    }
                }
            self.update_config_with_template_and_references(
                update_object,
                reference_details,
                True,
            )

    def update_config_with_node_references(self, interface, l3out_object):

        pod_id = interface.get("podID")
        node_id = interface.get("nodeID")

        if interface.get("pathType") == "pc":
            interface_details = self.mso.get_site_interface_details(
                self.template.get("l3outTemplate", {}).get("siteId"),
                port_channel_uuid=interface.get("pathRef"),
            )
            pod_id = interface_details.get("pod")
            node_id = interface_details.get("node")

        node = self.get_l3out_node(l3out_object.details, pod_id, node_id)
        if node and not isinstance(node, list):
            interface["node"] = node.details

    def check_template_when_name_is_provided(self, parameter):
        if parameter and parameter.get("name") and not (parameter.get("template") or parameter.get("template_id")):
            self.mso.fail_json(msg="Either 'template' or 'template_id' associated with '{}' must be provided".format(parameter.get("name")))

    def get_route_map_policy_for_multicast_uuid(self, route_map_policy_for_multicast_name):
        """
        Get the UUID of an Route Map Policy for Multicast by name.
        :param route_map_policy_for_multicast_name: Name of the Route Map Policy for Multicast to search for -> Str
        :return: UUID of the Route Map Policy for Multicast. -> Str
        """
        existing_route_map_policies = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", [])
        kv_list = [KVPair("name", route_map_policy_for_multicast_name)]
        match = self.get_object_by_key_value_pairs("Route Map Policy for Multicast", existing_route_map_policies, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_fabric_template_object_by_key_value(self, object_type, object_description, kv_list, fail_module=False):
        """
        Get the Fabric Policy by policy type and search criteria.
        The search criteria could be name and UUID of the object.
        :param object_type: The type of the object to retrieve the name for -> Str
        :param object_description: Description of the object to search for -> Str
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Dict | None: The processed result which could be:
              When the object is existing in the search list -> Dict
              When the object is not existing -> None
        """
        response_object = self.mso.request("getfabricpolicies?type={0}".format(object_type), "GET")
        search_list = response_object.get("items", [{"spec": {"policies": []}}])[0].get("spec", {}).get("policies", [])
        match = self.get_object_by_key_value_pairs(object_description, search_list, kv_list, fail_module)
        if match:
            return match.details

    def get_fabric_span_session(self, uuid=None, name=None, fail_module=False):
        """
        Get the Fabric SPAN Session by uuid or name.
        :param uuid: UUID of the Fabric SPAN Session to search for -> Str
        :param name: Name of the Fabric SPAN Session to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("monitoringTemplate", {}).get("template", {}).get("spanSessions", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("SPAN Session", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_fabric_span_session_source(self, name, search_list, fail_module=False):
        """
        Get the Fabric SPAN Session Source by name.
        :param name: Name of the Fabric SPAN Session Source to search for -> Str
        :param search_list: Objects to search through -> List.
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | List[Dict] | List[]: The processed result which could be:
                 When the Name is existing in the search list -> Dict
                 When both Name is None, and the search list is not empty -> List[Dict]
                 When both Name is None, and the search list is empty -> List[]
        """
        if name and search_list:  # Query a specific object
            return self.get_object_by_key_value_pairs("SPAN Session Source", search_list, [KVPair("name", name)], fail_module)
        return search_list  # Query all objects

    def get_application_template_contract(self, uuid=None, name=None, fail_module=False):
        """
        Get the Application Template Contract by uuid or name.
        :param uuid: UUID of the Contract to search for -> Str
        :param name: Name of the Contract to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("appTemplate", {}).get("template", {}).get("contracts", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Template Contract", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return existing_objects  # Query all objects
