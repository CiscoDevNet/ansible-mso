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


def append_update_ops_data(ops, existing_data, update_path, value, *existing_data_keys, op="replace"):
    """
    Append Update ops payload data.
    :param ops: Variable which contains the PATCH replace actions for the update operation -> List
    :param existing_data: Variable which contains the existing data -> Dict
    :param update_path: The object path is used to update an existing object -> Str
    :param value: Input value of the attribute which needs to be updated -> Any
    :param existing_data_keys: Additional positional arguments which is used to compare and update the existing data based on the sequence of keys -> Any
    :param op: Defaults to "replace" when not specified, value "remove" is used clear the existing configuration -> Str
    :return: None
                If attributes is not empty then the ops and existing_data are updated with the input value.

    Sample Inputs:
        ops = []
        existing_data = {
            "name": "L3OutInterfacePolicy",
            "bfdMultiHopPol": {
                "adminState": "enabled",
                "detectionMultiplier": 3,
                "minRxInterval": 250,
                "minTxInterval": 250
            },
        }
        update_path = "/tenantPolicyTemplate/template/l3OutIntfPolGroups/0"

        Sample existing_data_keys input format:
            To update the "bfdMultiHopPol -> adminState" value:
                existing_data_keys = "bfdMultiHopPol", "adminState"

        To update the top level key of the existing object:
            append_update_ops_data(ops, existing_data, update_path, "L3OutInterfacePolicy_NameUpdated", "name", op="replace")

        To create the nested object from the scratch when the object is not available:
            append_update_ops_data(ops, existing_data, update_path, dict(), "ospfIntfPol", op="replace")
            append_update_ops_data(ops, existing_data, update_path, dict(), "ospfIntfPol", "ifControl", op="replace")
            append_update_ops_data(ops, existing_data, update_path, True, "ospfIntfPol", "ifControl", "ignoreMtu", op="replace")

        After inserting the new object:
        existing_data = {
            "name": "L3OutInterfacePolicy",
            "ospfIntfPol": {
                "networkType": "broadcast",
                "prio": 1,
                "cost": 0,
                "ifControl": {
                    "advertiseSubnet": false,
                    "bfd": false,
                    "ignoreMtu": false,
                    "passiveParticipation": false
                },
                "helloInterval": 10,
                "deadInterval": 40,
                "retransmitInterval": 5,
                "transmitDelay": 1
            },
        }

        To update the nested key of the existing object:
            append_update_ops_data(ops, existing_data, update_path, True, "ospfIntfPol", "ifControl", "ignoreMtu", op="replace")

        To delete the nested object from the existing object:
            append_update_ops_data(ops, existing_data, update_path, None, "ospfIntfPol", "ifControl", op="remove")

        To delete the top level key from the existing object:
            append_update_ops_data(ops, existing_data, update_path, None, "ospfIntfPol", op="remove")
    """

    def recursive_update(data, path, keys, new_value):
        if len(keys) == 0:
            return
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

    if existing_data_keys:
        recursive_update(existing_data, update_path, existing_data_keys, value)
