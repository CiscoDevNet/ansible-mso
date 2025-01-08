# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy


def generate_api_endpoint(path, **kwargs):
    """
    Generates an API endpoint with query strings based on the provided keyword arguments.

    :param path: The base URL of the API endpoint. -> Str
    :param kwargs: Keyword arguments representing query parameters. -> Dict
    :return: A string representing the full API endpoint with query parameters. -> Str
    """
    return path if not kwargs else "{0}?{1}".format(path, "&".join(["{0}={1}".format(key, value) for key, value in kwargs.items()]))


def append_update_ops_data(ops, existing_data, update_path, replace_data=None, remove_data=None):
    """
    Append Update ops payload data.
    :param ops: Variable which contains the PATCH replace actions for the update operation -> List
    :param existing_data: Variable which contains the existing data -> Dict
    :param update_path: The object path is used to update an existing object -> Str
    :param replace_data: Defaults to None when not specified, expected a dictionary object. Which contains the attribute to be updated and its new value -> Dict
    :param remove_data: Defaults to None when not specified, expected a list of string or tuple, value used to clear the existing configuration -> List
    :return: None
                If attributes is not empty then the ops and existing_data are updated with the input value.

    Sample Existing Data:
    ---------------------
    existing_data = {
        "name": "name",
        "description": "description",
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {"adminState": "enabled"},
        },
        "bfdPol": {
            "adminState": "enabled",
            "detectionMultiplier": 3,
        }
    }

    ops = []
    update_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/0"
    replace_data = {
        ("name"): "new_name",
        "description": "new_description",
        ("ospfIntfPol"): dict(ifControl=dict(adminState="disabled"), cost=0)),
    }
    remove_data = [("bfdMultiHopPol", "ifControl", "adminState"), "bfdPol"]

    append_update_ops_data(ops, existing_data, update_path, replace_data, remove_data)

    Standard Output Data:
    ---------------------
    {
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {},
        },
        "name": "new_name",
        "description": "new_description",
        "ospfIntfPol": {
            "ifControl": {
                "adminState": "disbaled",
            },
            "cost": 0,
        },
    }

    API Input Data:
    ---------------
    [
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/name", "value": "new_name"},
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/description", "value": "new_description"},
        {
            "op": "replace",
            "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/ospfIntfPol",
            "value": {"ifControl": {"adminState": "disabled"}, "cost": 0},
        },
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdPol"},
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdMultiHopPol/ifControl/adminState"},
    ]
    """

    def recursive_replace(data, path, keys, new_value):
        key = keys[0]
        if len(keys) == 1:
            # Update the existing configuration
            if new_value is not None and data.get(key) != new_value:
                data[key] = new_value
                ops.append(
                    dict(
                        op="replace",
                        path="{}/{}".format(path, key),
                        value=copy.deepcopy(new_value),
                    )
                )
        elif key in data:
            recursive_replace(data[key], "{}/{}".format(path, key), keys[1:], new_value)

    def recursive_delete(data, path, keys):
        key = keys[0]
        if len(keys) == 1:
            # Clear the existing configuration
            if key in data:
                data.pop(key)
                ops.append(
                    dict(
                        op="remove",
                        path="{}/{}".format(path, key),
                    )
                )
        elif key in data:
            recursive_delete(data[key], "{}/{}".format(path, key), keys[1:])

    if replace_data:
        if not isinstance(replace_data, dict):
            raise TypeError("replace_data must be a dict")

        for key, value in replace_data.items():
            recursive_replace(existing_data, update_path, key if isinstance(key, tuple) else (key,), value)

    if remove_data:
        if not isinstance(remove_data, list):
            raise TypeError("remove_data must be a list of string or tuples")

        for key in remove_data:
            recursive_delete(existing_data, update_path, key if isinstance(key, tuple) else (key,))


def check_if_all_elements_are_none(values):
    """
    Checks if all the elements in the provided list are None.

    :param values: List of values to check. -> List
    :return: True if all elements are None, False otherwise. -> boo
    """
    return all(value is None for value in values)


def format_list_dict(list_dict, conversion_map):
    """
    Convert a Python list of dictionaries into its equivalent NDO API format.
    All keys must be defined in the keys map even if no conversion is needed for some keys.

    :param list_dict: The Python list of dictionaries to format. Can be an empty List or None -> List
    :param conversion_map: The mapping from the Ansible argument's keys to NDO API keys. Can also include the map between values -> Dict
    :return: The formatted list of dictionaries -> Dict

    Sample Input Data:
    ---------------------
    REDUCED_TARGET_COS_MAP = {
        "background": "cos0",
        "best_effort": "cos1",
        "excellent_effort": "cos2",
    }

    REDUCED_TARGET_DSCP_MAP = {
        "af11": "af11",
        "cs0": "cs0",
        "voice_admit": "voiceAdmit",
    }

    COS_CONVERSION_MAP = {
        "keys_map": {
            "dot1p_from": "dot1pFrom",
            "dot1p_to": "dot1pTo",
            "dscp_target": "dscpTarget",
            "target_cos": "targetCos",
            "qos_priority": "priority",
        },
        "values_map": {
            "dot1p_from": REDUCED_TARGET_COS_MAP,
            "dot1p_to": REDUCED_TARGET_COS_MAP,
            "dscp_target": REDUCED_TARGET_DSCP_MAP,
            "target_cos": REDUCED_TARGET_COS_MAP,
        },
    }

    ansible_cos_mappings = [
        {
            "dot1p_from": "background",
            "dot1p_to": "best_effort",
            "dscp_target": "voice_admit",
            "target_cos": "excellent_effort",
            "qos_priority": "level1",
        }
    ]

    formatted_cos_mappings = format_list_dict(ansible_cos_mappings, COS_KEYS_FORMAT_MAP)

    Output Data:
    ---------------------
    [
        {
            "dot1pFrom": "cos0",
            "dot1pTo": "cos1",
            "dscpTarget": "voiceAdmit",
            "targetCos": "cos2",
            "priority": "level1",
        }
    ]
    """
    if isinstance(list_dict, list) and isinstance(conversion_map, dict):
        keys_map, values_map = conversion_map.get("keys_map"), conversion_map.get("values_map")
        if isinstance(keys_map, dict) and isinstance(values_map, dict):

            def format_dict(d):  # format individual dictionary to its equivalent NDO API format
                formatted_dict = {}
                if isinstance(d, dict):
                    for key, value in d.items():
                        json_key = keys_map.get(key, "unknownKey")  # retrieve the equilavent NDO API formatted key
                        if not isinstance(json_key, str):
                            raise TypeError("the associated json key must be of type string, got:{0}".format(type(json_key)))
                        values_mapping = values_map.get(key)  # Check if there is a mapping between values associated with the current key
                        if values_mapping and isinstance(values_mapping, dict):
                            formatted_dict[json_key] = values_map[key].get(value, value)
                        else:
                            formatted_dict[json_key] = value  # in case there is no mapping between values
                else:
                    raise TypeError("items in list_dict must be dictionaries.")
                return formatted_dict

            return [format_dict(d) for d in list_dict]

        else:
            raise TypeError("keys_map and values_map must be of type dict.")

    elif list_dict is not None and not isinstance(list_dict, list):
        raise TypeError("list_dict can either be a list of dictionaries, an empty List or None.")

    elif not isinstance(conversion_map, dict):
        raise TypeError("conversion_map must be a dictionary.")
