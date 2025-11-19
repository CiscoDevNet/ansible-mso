# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
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
"""
