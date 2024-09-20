# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


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
