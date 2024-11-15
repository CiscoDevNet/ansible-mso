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


def append_update_ops_data(ops, existing_data, update_path, value, *args, op="replace"):
    """
    Append Update ops payload data.
    :param ops: Variable which contains the PATCH replace actions for the update operation -> List
    :param existing_data: Variable which contains the existing data -> Dict
    :param update_path: The object path is used to update an existing object -> Str
    :param value: Input value of the attribute which needs to be updated -> Any
    :param args: Extra arguments which is used to compare and update the existing data -> Any
    :param op: Defaults to "replace" when not specified, value "remove" is used clear the existing configuration -> Str
    :return: None
                If args is not empty then the ops and existing_data are updated with the input value.
    """

    def recursive_update(data, current_path, keys, new_value):
        if len(keys) == 0:
            return
        key = keys[0]

        if len(keys) == 1:
            # Update the existing configuration
            if new_value is not None and data.get(key) != new_value:
                data[key] = new_value
                ops.append(
                    dict(
                        op=op,
                        path="{}/{}".format(current_path, key),
                        value=copy.deepcopy(new_value),
                    )
                )
            # Clear the existing configuration
            elif op == "remove":
                data.pop(key, None)
                ops.append(
                    dict(
                        op=op,
                        path="{}/{}".format(current_path, key),
                    )
                )

        elif key in data:
            recursive_update(data[key], "{}/{}".format(current_path, key), keys[1:], new_value)

    if args:
        if isinstance(args[0], tuple):
            recursive_update(existing_data, update_path, args[0], value)
        else:
            recursive_update(existing_data, update_path, args, value)
