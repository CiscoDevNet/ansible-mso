#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_esg_annotation
short_description: Manage ESG annotations in schema templates
description:
- Manage Endpoint Security Group (ESG) annotations in Application Profiles (ANPs) in schema templates on Cisco ACI Multi-Site.
- This module is only supported on ND v4.1 (NDO v5.1) and later.
author:
- Akini Ross (@akinross)
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
  anp:
    description:
    - The ANP that contains the ESG.
    type: str
    required: true
  esg:
    description:
    - The name of the ESG that contains the annotation.
    type: str
    required: true
  annotation_key:
    description:
    - The key of the annotation.
    - Required when O(state) is C(present) or C(absent).
    - This argument is not required when querying all annotations on the ESG.
    type: str
    aliases: [ key ]
  annotation_value:
    description:
    - The value of the annotation.
    - Required when O(state) is C(present), including updates.
    type: str
    aliases: [ value ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an annotation or all annotations on the ESG.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The O(schema) and O(template) must exist before using this module.
  Use M(cisco.mso.mso_schema_template) to create the schema and template.
- The O(anp) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_anp) to create the ANP.
- The O(esg) must exist before using this module.
  Use M(cisco.mso.mso_schema_template_anp_esg) to create the ESG.
seealso:
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_esg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an ESG annotation
  cisco.mso.mso_schema_template_anp_esg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    annotation_key: annotation_key_1
    annotation_value: annotation_value_1
    state: present

- name: Update an ESG annotation
  cisco.mso.mso_schema_template_anp_esg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    annotation_key: annotation_key_1
    annotation_value: annotation_value_1_updated
    state: present

- name: Query a specific ESG annotation
  cisco.mso.mso_schema_template_anp_esg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    annotation_key: annotation_key_1
    state: query
  register: query_result

- name: Query all annotations on an ESG
  cisco.mso.mso_schema_template_anp_esg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    state: query
  register: query_result

- name: Remove an ESG annotation
  cisco.mso.mso_schema_template_anp_esg_annotation:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    esg: ESG 1
    annotation_key: annotation_key_1
    state: absent
"""

RETURN = r"""
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        esg=dict(type="str", required=True),
        annotation_key=dict(type="str", aliases=["key"], no_log=False),  # This parameter is not required for querying all objects
        annotation_value=dict(type="str", aliases=["value"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["annotation_key"]],
            ["state", "present", ["annotation_key", "annotation_value"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp").replace(" ", "")
    esg = module.params.get("esg")
    annotation_key = module.params.get("annotation_key")
    annotation_value = module.params.get("annotation_value")
    state = module.params.get("state")

    mso = MSOModule(module)
    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_esg(esg)

    if state == "query":
        if annotation_key is None:
            mso.existing = mso_schema.schema_objects["template_anp_esg"].details.get("tagAnnotations") or []
        else:
            mso_schema.set_template_anp_esg_annotation(annotation_key)
            mso.existing = mso_schema.schema_objects.get("template_anp_esg_annotation").details
        mso.exit_json()

    mso_schema.set_template_anp_esg_annotation(annotation_key, fail_module=False)
    annotation = mso_schema.schema_objects.get("template_anp_esg_annotation")
    mso.previous = mso.existing = annotation.details if annotation else mso.existing

    annotations_path = "/templates/{0}/anps/{1}/esgs/{2}/tagAnnotations".format(template, anp, esg)
    ops = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(annotations_path, annotation.index)))

    elif state == "present":
        payload = dict(tagKey=annotation_key, tagValue=annotation_value)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            mso.existing = copy.deepcopy(mso.previous)
            append_update_ops_data(ops, mso.existing, "{0}/{1}".format(annotations_path, annotation.index), payload)
        else:
            if mso_schema.schema_objects["template_anp_esg"].details.get("tagAnnotations") is None:
                # NDO can return tagAnnotations as null, which cannot be appended to using /-.
                # JSON Patch add at the collection path creates the array or replaces the existing null value.
                ops.append(dict(op="add", path=annotations_path, value=[mso.sent]))
            else:
                ops.append(dict(op="add", path="{0}/-".format(annotations_path), value=mso.sent))
            mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
