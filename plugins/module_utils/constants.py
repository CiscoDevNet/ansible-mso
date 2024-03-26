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

YES_OR_NO_TO_BOOL_STRING_MAP = {"yes": "true", "no": "false", True: "yes", False: "no"}

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

AZURE_L4L7_CONNECTOR_TYPE_MAP = {
    "none": "none",
    "redirect": "redir",
    "source_nat": "snat",
    "destination_nat": "dnat",
    "source_and_destination_nat": "snat_dnat",
}

LISTENER_PROTOCOLS = ["http", "https", "tcp", "udp", "tls", "inherit"]

LISTENER_SECURITY_POLICY_MAP = {
    "default": "default",
    "elb_sec_2016_18": "eLBSecurityPolicy-2016-08",
    "elb_sec_fs_2018_06": "eLBSecurityPolicy-FS-2018-06",
    "elb_sec_tls_1_2_2017_01": "eLBSecurityPolicy-TLS-1-2-2017-01",
    "elb_sec_tls_1_2_ext_2018_06": "eLBSecurityPolicy-TLS-1-2-Ext-2018-06",
    "elb_sec_tls_1_1_2017_01": "eLBSecurityPolicy-TLS-1-1-2017-01",
    "elb_sec_2015_05": "eLBSecurityPolicy-2015-05",
    "elb_sec_tls_1_0_2015_04": "eLBSecurityPolicy-TLS-1-0-2015-04",
    "app_gw_ssl_default": "AppGwSslPolicyDefault",
    "app_gw_ssl_2015_501": "AppGwSslPolicy20150501",
    "app_gw_ssl_2017_401": "AppGwSslPolicy20170401",
    "app_gw_ssl_2017_401s": "AppGwSslPolicy20170401S",
}

LISTENER_ACTION_TYPE_MAP = {"fixed_response": "fixedResponse", "forward": "forward", "redirect": "redirect", "ha_port": "haPort"}

LISTENER_CONTENT_TYPE_MAP = {"text_plain": "textPlain", "text_css": "textCSS", "text_html": "textHtml", "app_js": "appJS", "app_json": "appJson"}

LISTENER_REDIRECT_CODE_MAP = {
    "unknown": "unknown",
    "permanently_moved": "permMoved",
    "found": "found",
    "see_other": "seeOther",
    "temporary_redirect": "temporary",
}
