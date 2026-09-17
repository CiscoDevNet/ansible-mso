#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_external_epg
short_description: Manage external EPGs in schema templates
description:
- Manage external EPGs in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  external_epg:
    description:
    - The name of the external EPG to manage.
    type: str
    aliases: [ name, externalepg ]
  description:
    description:
    - The description of external EPG is supported on versions of MSO that are 3.3 or greater.
    type: str
  type:
    description:
    - The type of external epg.
    - anp needs to be associated with external epg when the type is cloud.
    - l3out can be associated with external epg when the type is on-premise.
    - The C(cloud) value is deprecated on Nexus Dashboard 4.x (NDO 5.x) because cloud external EPGs are no longer supported.
      It will be removed in a future version of this collection.
    type: str
    choices: [ on-premise, cloud ]
    default: on-premise
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  vrf:
    description:
    - The VRF associated with the external epg.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current template.
        type: str
  l3out:
    description:
    - The L3Out associated with the external epg.
    type: dict
    suboptions:
      name:
        description:
        - The name of the L3Out to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced L3Out.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced L3Out.
        - If this parameter is unspecified, it defaults to the current template.
        type: str
  anp:
    description:
    - The anp associated with the external epg.
    - This parameter is deprecated on Nexus Dashboard 4.x (NDO 5.x) because it is only used by cloud external EPGs.
      It will be removed in a future version of this collection.
    type: dict
    suboptions:
      name:
        description:
        - The name of the anp to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced anp.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced anp.
        - If this parameter is unspecified, it defaults to the current template.
        type: str
  preferred_group:
    description:
    - Preferred Group is enabled for this External EPG or not.
    type: bool
  qos_level:
    description:
    - The QoS Level parameter is supported on versions of MSO/NDO that are 4.3 or greater.
    - Defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ unspecified, level1, level2, level3, level4, level5, level6 ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new external EPG
  cisco.mso.mso_schema_template_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: External EPG 1
    vrf:
      name: VRF
      schema: Schema 1
      template: Template 1
    state: present

- name: Remove an external EPG
  cisco.mso.mso_schema_template_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: external EPG1
    state: absent

- name: Query a specific external EPGs
  cisco.mso.mso_schema_template_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    external_epg: external EPG1
    state: query
  register: query_result

- name: Query all external EPGs
  cisco.mso.mso_schema_template_external_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import QOS_LEVEL
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        external_epg=dict(type="str", aliases=["name", "externalepg"]),  # This parameter is not required for querying all objects
        description=dict(type="str"),
        display_name=dict(type="str"),
        vrf=dict(type="dict", options=mso_reference_spec()),
        l3out=dict(type="dict", options=mso_reference_spec()),
        anp=dict(type="dict", options=mso_reference_spec()),
        preferred_group=dict(type="bool"),
        type=dict(type="str", default="on-premise", choices=["on-premise", "cloud"]),
        qos_level=dict(type="str", choices=QOS_LEVEL),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["external_epg"]],
            ["state", "present", ["external_epg", "vrf"]],
            ["type", "cloud", ["anp"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    external_epg = module.params.get("external_epg")
    description = module.params.get("description")
    display_name = module.params.get("display_name")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf.get("template").replace(" ", "")
    l3out = module.params.get("l3out")
    if l3out is not None and l3out.get("template") is not None:
        l3out["template"] = l3out.get("template").replace(" ", "")
    anp = module.params.get("anp")
    if anp is not None and anp.get("template") is not None:
        anp["template"] = anp.get("template").replace(" ", "")
    preferred_group = module.params.get("preferred_group")
    type_ext_epg = module.params.get("type")
    qos_level = module.params.get("qos_level")
    state = module.params.get("state")

    if type_ext_epg == "cloud" or anp is not None:
        module.deprecate(
            msg="The 'type=cloud' value and 'anp' parameter are deprecated because cloud external EPGs are no longer supported in "
            "Nexus Dashboard 4.x (NDO 5.x) releases.",
            version="4.0.0",
            collection_name="cisco.mso",
        )

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get external EPGs
    external_epgs = [e.get("name") for e in schema_obj.get("templates")[template_idx]["externalEpgs"]]

    if external_epg is not None and external_epg in external_epgs:
        external_epg_idx = external_epgs.index(external_epg)
        mso.existing = schema_obj.get("templates")[template_idx]["externalEpgs"][external_epg_idx]
        mso.existing.pop("externalEpgRef", None)
        if mso.existing.get("anpRef") is None:
            mso.existing.pop("anpRef", None)
        mso.recursive_dict_from_ref(mso.existing)

    if state == "query":
        if external_epg is None:
            mso.existing = schema_obj.get("templates")[template_idx]["externalEpgs"]
            for template_external_epg in mso.existing:
                template_external_epg.pop("externalEpgRef", None)
                if template_external_epg.get("anpRef") is None:
                    template_external_epg.pop("anpRef", None)
                mso.recursive_dict_from_ref(template_external_epg)
        elif not mso.existing:
            mso.fail_json(msg="External EPG '{external_epg}' not found".format(external_epg=external_epg))
        mso.exit_json()

    eepgs_path = "/templates/{0}/externalEpgs".format(template)
    eepg_path = "/templates/{0}/externalEpgs/{1}".format(template, external_epg)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=eepg_path))

    elif state == "present":
        vrf_ref = mso.make_reference(vrf, "vrf", schema_id, template)
        l3out_ref = mso.make_reference(l3out, "l3out", schema_id, template)
        anp_ref = mso.make_reference(anp, "anp", schema_id, template)
        if display_name is None and not mso.existing:
            display_name = external_epg

        payload = dict(
            name=external_epg,
            displayName=display_name,
            vrfRef=vrf_ref,
            preferredGroup=preferred_group,
        )

        if description is not None:
            payload.update(description=description)

        if type_ext_epg == "cloud":
            payload["extEpgType"] = "cloud"
            payload["anpRef"] = anp_ref
        else:
            payload["l3outRef"] = l3out_ref

        if qos_level:
            payload["qosPriority"] = qos_level

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, eepg_path, payload)
        else:
            ops.append(dict(op="add", path=eepgs_path + "/-", value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
