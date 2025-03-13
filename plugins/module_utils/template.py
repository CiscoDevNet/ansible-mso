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
    def __init__(self, mso_module, template_type=None, template_name=None, template_id=None):
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

        if template_id:
            # Checking if the template with id exists to avoid error: MSO Error 400: Template ID 665da24b95400f375928f195 invalid
            self.template_summary = self.mso.get_obj(self.summaries_path, templateId=self.template_id)
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_id)
                self.template = self.mso.query_obj(self.template_path)
                self.template_name = self.template.get("displayName")
                self.template_type = self.template.get("templateType")
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
                self.summaries_path, templateName=self.template_name, templateType=TEMPLATE_TYPES[template_type]["template_type"]
            )
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_summary.get("templateId"))
                self.template = self.mso.query_obj(self.template_path)
                self.template_id = self.template.get("templateId")
                self.template_type = self.template.get("templateType")

        elif template_type:
            self.template = self.mso.query_objs(self.summaries_path, templateType=TEMPLATE_TYPES[template_type]["template_type"])
        else:
            self.template = self.mso.query_objs(self.summaries_path)

        # Remove unwanted keys from existing object for better output and diff compares
        if isinstance(self.template, dict):
            for key in ["_updateVersion", "version"]:
                self.template.pop(key, None)

    @staticmethod
    def get_object_from_list(search_list, kv_list):
        """
        Get the first matched object from a list of mso object dictionaries.
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :return: The index and details of the object. -> Item (Named Tuple)
                 Values of provided keys of all existing objects. -> List
        """

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

    def get_l3out_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the L3Out by uuid or name.
        :param uuid: UUID of the L3Out to search for -> Str
        :param name: Name of the L3Out to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_l3outs = self.template.get("l3outTemplate", {}).get("l3outs", [])
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

    def get_tenant_policy_uuid(self, tenant_template, policy_name, policy_type):
        """
        Get the UUID of a Tenant Policy by name.
        :param tenant_template: The tenant object -> Dict
        :param policy_name: Name of the policy -> Str
        :param policy_type: The type of the policy specified in the API response -> Str
        :return: UUID of the tenant policy -> Str
        """
        existing_policies = tenant_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get(policy_type, [])
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
            return config_data
        return config_data

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
