#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_bulk_staticport
short_description: Manage site-local EPG static ports in schema template
description:
- Manage site-local EPG static ports in schema template on Cisco ACI Multi-Site.
author:
- Anvitha Jain (@anvjain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: yes
  site:
    description:
    - The name of the site.
    type: str
    required: yes
  template:
    description:
    - The name of the template.
    type: str
    required: yes
  anp:
    description:
    - The name of the ANP.
    type: str
    required: yes
  epg:
    description:
    - The name of the EPG.
    type: str
    required: yes
  type:
    description:
    - The path type of the static port
    - vpc is used for a Virtual Port Channel
    - dpc is used for a Direct Port Channel
    - port is used for a single interface
    type: str
    choices: [ port, vpc, dpc ]
    default: port
  pod:
    description:
    - The pod of the static port.
    type: str
  leaf:
    description:
    - The leaf of the static port.
    type: str
  fex:
    description:
    - The fex id of the static port.
    type: str
  path:
    description:
    - The path of the static port.
    type: str
  vlan:
    description:
    - The port encap VLAN id of the static port.
    type: int
  deployment_immediacy:
    description:
    - The deployment immediacy of the static port.
    - C(immediate) means B(Deploy immediate).
    - C(lazy) means B(deploy on demand).
    type: str
    choices: [ immediate, lazy ]
    default: lazy
  mode:
    description:
    - The mode of the static port.
    - C(native) means B(Access (802.1p)).
    - C(regular) means B(Trunk).
    - C(untagged) means B(Access (untagged)).
    type: str
    choices: [ native, regular, untagged ]
    default: untagged
  primary_micro_segment_vlan:
    description:
    - Primary micro-seg VLAN of static port.
    type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing an object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_anp_epg
- module: cisco.mso.mso_schema_template_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new static port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    vlan: 126
    deployment_immediacy: immediate
    state: present
  delegate_to: localhost

- name: Add a new static fex port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    fex: 151
    path: eth1/1
    vlan: 126
    deployment_immediacy: lazy
    state: present
  delegate_to: localhost

- name: Add a new static VPC to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    pod: pod-1
    leaf: 101-102
    path: ansible_polgrp
    vlan: 127
    type: vpc
    mode: untagged
    deployment_immediacy: lazy
    state: present
  delegate_to: localhost

- name: Remove a static port from a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    state: absent
  delegate_to: localhost

- name: Query a specific site EPG static port
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all site EPG static ports
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema



# from ansible.module_utils.basic import AnsibleModule
# from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        type=dict(type="str", default="port", choices=["port", "vpc", "dpc"]),
        pod=dict(type="str"),  # This parameter is not required for querying all objects
        leaf=dict(type="str"),  # This parameter is not required for querying all objects
        fex=dict(type="str"),  # This parameter is not required for querying all objects
        path=dict(type="str"),  # This parameter is not required for querying all objects
        vlan=dict(type="int"),  # This parameter is not required for querying all objects
        primary_micro_segment_vlan=dict(type="int"),  # This parameter is not required for querying all objects
        deployment_immediacy=dict(type="str", default="lazy", choices=["immediate", "lazy"]),
        mode=dict(type="str", default="untagged", choices=["native", "regular", "untagged"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["type", "pod", "leaf", "path", "vlan"]],
            ["state", "present", ["type", "pod", "leaf", "path", "vlan"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    path_type = module.params.get("type")
    pod = module.params.get("pod")
    leaf = module.params.get("leaf")
    fex = module.params.get("fex")
    path = module.params.get("path")
    vlan = module.params.get("vlan")
    primary_micro_segment_vlan = module.params.get("primary_micro_segment_vlan")
    deployment_immediacy = module.params.get("deployment_immediacy")
    mode = module.params.get("mode")
    state = module.params.get("state")

    if path_type == "port" and fex is not None:
        # Select port path for fex if fex param is used
        portpath = "topology/{0}/paths-{1}/extpaths-{2}/pathep-[{3}]".format(pod, leaf, fex, path)
    elif path_type == "vpc":
        portpath = "topology/{0}/protpaths-{1}/pathep-[{2}]".format(pod, leaf, path)
    else:
        portpath = "topology/{0}/paths-{1}/pathep-[{2}]".format(pod, leaf, path)

    mso = MSOModule(module)

    # Get schema objects
    mso_schema = MSOSchema(mso, schema, template, site)
    mso_objects = mso_schema.schema_objects

    # Verifies ANP  and EPG exists at template level
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    # Verifies if ANP exists at site level 
    mso_schema.set_site_anp(anp , fail_module=False) 


    payload = dict()
    ops = []
    epg_path = ""

    # If anp not at site level but exists at template level
    if not mso_objects.get("site_anp"):
        op_path = "/sites/{0}-{1}/anps/-".format(mso_objects.get("site").details.get("siteId"), template)
        payload.update(
            anpRef=dict(
                schemaId=mso_schema.id,
                templateName=template,
                anpName=anp,
            ),
        )
    else :
        anp_path = "/sites/{0}-{1}/anps".format(mso_objects.get("site").details.get("siteId"), template)
        mso_schema.set_site_anp_epg(epg, fail_module=False) 

    # If anp already at site level AND if epg not at site level (or) anp not at site level
    if mso_objects.get("site_anp") and not mso_objects.get("site_anp_epg") or "anpRef" in payload:
		# EPG at template level but not at site level. Create payload at site level for EPG
        if mso_objects.get("template_anp_epg"):
            new_epg = dict(
                epgRef=dict(
                    schemaId=mso_schema.id,
                    templateName=template,
                    anpName=anp,
                    epgName=epg,
                )
            )

            # If anp not in payload then, anp already exists at site level. New payload will only have new EPG payload
            if "anpRef" not in payload:
                op_path = "{0}/{1}/epgs/-".format(anp_path, anp)
                payload = new_epg
            else:
                # If anp in payload, anp exists at site level. Update payload with EPG payload
                payload["epgs"] = [new_epg]
    else:
		# If anp and epg exists at site level
        epg_path = "{0}/{1}/epgs".format(anp_path, anp)


    # Get Leaf
    # If anp at site level and epg is at site level
    if "anpRef" not in payload and "epgRef" not in payload:
        portpaths = [p.get("path") for p in mso_objects.get("site_anp_epg").details.get("staticPorts")]
        if portpath in portpaths:
            portpath_idx = portpaths.index(portpath)
            port_path = "{0}/{1}/staticPorts/{2}".format(epg_path, epg, portpath_idx)
            mso.existing = mso_objects.get("site_anp_epg").details.get("staticPorts")[portpath_idx]



    if state == "query":
        if leaf is None or vlan is None:
            mso.existing = mso_objects.get("site_anp_epg").details.get("staticPorts")
        elif not mso.existing:
            mso.fail_json(msg="Static port '{portpath}' not found".format(portpath=portpath))
        mso.exit_json()

    ports_path = "{0}/{1}/staticPorts".format(epg_path, epg)

    new_leaf = dict(
        deploymentImmediacy=deployment_immediacy,
        mode=mode,
        path=portpath,
        portEncapVlan=vlan,
        type=path_type,
    )
    if primary_micro_segment_vlan:
        new_leaf.update(microSegVlan=primary_micro_segment_vlan)

    # If payload is empty, anp and EPG already exist at site level
    if not payload:
        op_path = ports_path + "/-"
        payload = new_leaf
    # If payload exists
    else:
        # If anp already exists at site level
        if "anpRef" not in payload:
            payload["staticPorts"] = [new_leaf]
        else:
            payload["epgs"][0]["staticPorts"] = [new_leaf]

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=port_path))

    elif state == "present":

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=port_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = new_leaf

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
