# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  annotations:
    description:
    - The list of annotations.
    - Providing an empty list will remove the O(annotations) from the parent object.
    type: list
    elements: dict
    suboptions:
      key:
        description:
        - The annotation key.
        type: str
      value:
        description:
        - The  value associated with O(annotations.key).
        type: str
  policy_tags:
    description:
    - The list of Policy Tags.
    - Providing an empty list will remove the O(policy_tags) from the parent object.
    type: list
    elements: dict
    aliases: [ tags ]
    suboptions:
      key:
        description:
        - The Policy Tag key.
        type: str
      value:
        description:
        - The value associated with O(policy_tags.key).
        type: str
"""
