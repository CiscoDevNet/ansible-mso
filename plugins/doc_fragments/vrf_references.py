# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
  vrf:
    description:
    - The VRF reference details.
    type: dict
    suboptions:
      uuid:
        description:
        - The UUID of the VRF.
        - This parameter can be used instead of O(vrf.reference).
        type: str
      reference:
        description:
        - The reference details of the VRF.
        - This parameter can be used instead of O(vrf.uuid).
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the VRF.
            required: true
            type: str
          schema:
            description:
            - The schema associated with the VRF.
            required: true
            type: str
          template:
            description:
            - The template ID associated with the VRF.
            required: true
            type: str
"""
