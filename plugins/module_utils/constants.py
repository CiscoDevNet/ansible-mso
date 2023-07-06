FILTER_KEY_MAP = {
    "both-way": "filterRelationships",
    "consumer-to-provider": "filterRelationshipsConsumerToProvider",
    "provider-to-consumer": "filterRelationshipsProviderToConsumer",
}

PRIORITY_MAP = {
    "default": "default",
    "lowest_priority": "level1",
    "medium_priority": "level2",
    "highest_priority": "level3",
}

SERVICE_NODE_CONNECTOR_MAP = {
    "bd": {"id": "bd", "connector_type": "general"}
    # 'external_epg': {'id': 'externalEpg', 'connector_type': 'route-peering'}
}

YES_OR_NO_TO_BOOL_STRING_MAP = {"yes": "true", "no": "false"}

NDO_4_UNIQUE_IDENTIFIERS = ["templateID", "autoRouteTargetImport", "autoRouteTargetExport"]

NDO_API_VERSION_FORMAT = "/mso/api/{api_version}"
NDO_API_VERSION_PATH_FORMAT = "/mso/api/{api_version}/{path}"

EPG_U_SEG_ATTR_TYPE_MAP = {
    "ip": "ip",
    "mac": "mac",
    "dns": "dns",
    "vm_datacenter": "rootContName",
    "vm_hypervisor_identifier": "hv",
    "vm_operating_system": "guest-os",
    "vm_tag": "tag",
    "vm_identifier": "vm",
    "vmm_domain": "domain",
    "vm_name": "vm-name",
    "vnic_dn": "vnic",
}

EPG_U_SEG_ATTR_OPERATOR_LIST = ["equals", "contains", "starts_with", "ends_with"]
