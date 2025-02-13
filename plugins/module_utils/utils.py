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
    :return: True if all elements are None, False otherwise. -> Bool
    """
    return all(value is None for value in values)


def map_keys_to_new_dict(input_dict, key_mapping):
    """
    Transform keys of the input dictionary based on a key mapping and return a new dictionary.

    This function creates a new dictionary by mapping keys from the input dictionary to new keys
    as specified in the key mapping. It only includes keys present in the key mapping.

    :param input_dict: The original dictionary with keys to be transformed -> Dict
    :param key_mapping: A dictionary where each key-value pair maps an original key to a new key -> Dict
    :return: A new dictionary with keys transformed according to the key mapping. If input_dict is empty, returns an empty dictionary -> Dict

    Sample Data:
    ------------
        key_mapping = {
            "multicast": "afMast",
            "unicast": "afUcast",
        }

        input_dict = {
            "multicast": True,
            "unicast": False,
        }

    Sample Output:
    --------------
        return_value = {
            "afMast": True,
            "afUcast": False,
        }
    """
    output_dict = {}

    if input_dict:
        for old_key, new_key in key_mapping.items():
            output_dict[new_key] = input_dict.get(old_key)

    return output_dict


def remove_none_values(data):
    """
    Recursively removes all key-value pairs where the value is None from a dictionary,
    including nested dictionaries and lists of dictionaries. If a dictionary becomes empty
    after removals, it is set to None if it is a value in another dictionary or removed if in a list.

    :param data: The original data structure (dictionary or list) from which None values should be removed -> List, Dict
    :return: A new data structure with all None values removed, or None if the structure is empty -> List, Dict or None

    Sample Data:
    ------------
        data = {
            "multicast": None,
            "unicast": False,
        }

    Sample Output:
    --------------
        return_value = {
            "unicast": False,
        }
    """
    if isinstance(data, dict):
        cleaned_dict = {key: remove_none_values(value) for key, value in data.items() if value is not None}
        return {key: value for key, value in cleaned_dict.items() if value is not None} or None
    elif isinstance(data, list):
        cleaned_list = [remove_none_values(item) for item in data if item is not None]
        return [item for item in cleaned_list if item is not None] or None
    else:
        return data


def merge_sub_dict_into_main(main_dict, sub_dict, *prefix_keys):
    """
    Merge a sub-dictionary into the main dictionary by transforming its keys.

    Each key in the sub-dictionary is prefixed with a sequence of keys provided as arguments,
    and the resulting keys are stored as tuples in the main dictionary with their corresponding values.

    :param main_dict: The dictionary to be updated with transformed keys from the sub-dictionary -> Dict
    :param sub_dict: The dictionary whose keys and values are to be transformed and merged -> Dict
    :param prefix_keys: A sequence of keys to be used as a prefix for each key in the sub-dictionary -> List, Tuple
    :return: The updated main dictionary with keys from the sub-dictionary transformed and merged -> Dict

    Sample Data:
    ------------
        main_dict = {
            "peerAddressV4": "1.1.1.1",
            "peerAddressV6": "1::9/16",
            "peerAsn": 1,
        }
        sub_dict = {
            "afMast": True,
            "afUcast": False,
        }
        prefix_keys = ("addressTypeControls")

    Sample Output:
    --------------
        return_value = {
            "peerAddressV4": "1.1.1.1",
            "peerAddressV6": "1::9/16",
            "peerAsn": 1,
            ("addressTypeControls", "afMast"): True,
            ("addressTypeControls", "afUcast"): False,
        }
    """
    if sub_dict:
        prefix_list = list(prefix_keys)

        for key, value in sub_dict.items():
            main_dict[tuple(prefix_list + [key])] = value

    return main_dict


def get_template_object_name_by_uuid(mso, object_type, uuid):
    """
    Retrieve the name of a specific object type in the MSO template using its UUID.

    :param mso: An instance of the MSO class, which provides methods for making API requests -> MSO Class instance
    :param object_type: The type of the object to retrieve the name for -> Str
    :param uuid: The UUID of the object to retrieve the name for -> Str
    :return: Str | None: The processed result which could be:
          When the UUID is existing, returns object name -> Str
          When the UUID is not existing -> None
    """
    response_object = mso.request("templates/objects?type={0}&uuid={1}".format(object_type, uuid), "GET")
    if response_object:
        return response_object.get("name")
