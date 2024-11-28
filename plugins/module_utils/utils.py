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
    # if not kwargs:
    #     return path

    # query_strings = ["{0}={1}".format(key, value) for key, value in kwargs.items()]
    # query_string = "&".join(query_strings)
    # full_url = "{0}?{1}".format(path, query_string)

    # return full_url

    return path if not kwargs else "{0}?{1}".format(path, "&".join(["{0}={1}".format(key, value) for key, value in kwargs.items()]))


def append_update_ops_data(ops, existing_data, update_path, changes=None, op="replace"):
    """
    Append Update ops payload data.
    :param ops: Variable which contains the PATCH replace actions for the update operation -> List
    :param existing_data: Variable which contains the existing data -> Dict
    :param update_path: The object path is used to update an existing object -> Str
    :param changes: Defaults to None when not specified, expected a dictionary object. Which contains the attribute to be updated and its new value -> Dict
    :param op: Defaults to "replace" when not specified, value "remove" is used clear the existing configuration -> Str
    :return: None
                If attributes is not empty then the ops and existing_data are updated with the input value.

    Sample data for the replace call:
    ---------------------------------

    Sample Existing Data:
    ---------------------
    existing_data = {
        "bfdMultiHopPol": {"adminState": "enabled", "minRxInterval": 250},
        "bfdPol": {"adminState": "enabled", "detectionMultiplier": 3},
        "name": "irp_1",
    }
    ops = []
    update_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/0"

    replace_data = {
        ("name"): "new_name",
        "description": "new_description",
        ("bfdMultiHopPol", "ifControl"): dict(),
        ("bfdMultiHopPol", "ifControl", "adminState"): "enabled",
        ("ospfIntfPol"): dict(ifControl=dict(adminState="disbaled"), cost=0),
    }

    append_update_ops_data(ops, existing_data, interface_routing_policy_path, replace_data)

    Replace function call output data:
    ----------------------------------

    Standard Output Data:
    ---------------------
    {
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {"adminState": "enabled"},
        },
        "bfdPol": {
            "adminState": "enabled",
            "detectionMultiplier": 3,
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
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdMultiHopPol/ifControl", "value": {}},
        {"op": "replace", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdMultiHopPol/ifControl/adminState", "value": "enabled"},
        {
            "op": "replace",
            "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/ospfIntfPol",
            "value": {"ifControl": {"adminState": "disbaled"}, "cost": 0},
        },
    ]

    ----------------------------------------------------------------

    Sample data for the remove call:
    --------------------------------

    existing_data = {
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {"adminState": "enabled"},
        },
        "bfdPol": {
            "adminState": "enabled",
            "detectionMultiplier": 3,
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
    ops = []
    update_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/0"

    remove_data = {
        "description": None,
        "bfdPol": None,
        ("bfdMultiHopPol", "ifControl", "adminState"): None,
        ("ospfIntfPol"): None,
    }

    append_update_ops_data(ops, existing_data, interface_routing_policy_path, remove_data, op="remove")

    Remove function call output data:
    ---------------------------------

    Standard Output Data:
    ---------------------
    {
        "bfdMultiHopPol": {
            "adminState": "enabled",
            "minRxInterval": 250,
            "ifControl": {},
        },
        "name": "new_name",
    }

    API Input Data:
    -----------------
    [
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/description"},
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdPol"},
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/bfdMultiHopPol/ifControl/adminState"},
        {"op": "remove", "path": "/tenantPolicyTemplate/template/l3OutIntfPolGroups/1/ospfIntfPol"},
    ]
    """

    def recursive_update(data, path, keys, new_value):
        key = keys[0]
        if len(keys) == 1:
            # Update the existing configuration
            if new_value is not None and data.get(key) != new_value and op == "replace":
                data[key] = new_value
                ops.append(
                    dict(
                        op=op,
                        path="{}/{}".format(path, key),
                        value=copy.deepcopy(new_value),
                    )
                )
            # Clear the existing configuration
            elif op == "remove" and key in data:
                data.pop(key)
                ops.append(
                    dict(
                        op=op,
                        path="{}/{}".format(path, key),
                    )
                )

        elif key in data:
            recursive_update(data[key], "{}/{}".format(path, key), keys[1:], new_value)

    valid_ops = ["replace", "remove"]
    if op not in valid_ops:
        raise ValueError("Invalid op value. Expected one of: {0}. Got: {1}".format(valid_ops, op))

    if changes:
        for key, value in changes.items():
            if isinstance(key, tuple):
                recursive_update(existing_data, update_path, key, value)
            else:
                recursive_update(existing_data, update_path, (key,), value)
