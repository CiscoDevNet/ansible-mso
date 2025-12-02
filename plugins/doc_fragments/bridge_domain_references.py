# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
  bridge_domain:
    description:
    - The Bridge Domain reference details.
    type: dict
    aliases: [ bd ]
    suboptions:
      uuid:
        description:
        - The UUID of the Bridge Domain.
        - This parameter can be used instead of O(bridge_domain.reference).
        type: str
      reference:
        description:
        - The reference details of the Bridge Domain.
        - This parameter can be used instead of O(bridge_domain.uuid).
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the Bridge Domain.
            required: true
            type: str
          schema:
            description:
            - The name of the schema associated with the Bridge Domain.
            - This parameter can be used instead of O(bridge_domain.reference.schema_id).
            type: str
          schema_id:
            description:
            - The schema ID associated with the Bridge Domain.
            - This parameter can be used instead of O(bridge_domain.reference.schema).
            type: str
          template:
            description:
            - The name of the template associated with the Bridge Domain.
            - This parameter can be used instead of O(bridge_domain.reference.template_id).
            type: str
          template_id:
            description:
            - The template ID associated with the Bridge Domain.
            - This parameter can be used instead of O(bridge_domain.reference.template).
            type: str
"""
