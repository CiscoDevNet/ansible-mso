# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, delete_none_values


class L3OutNode:
    def __init__(self, details, l3out_mso_template, l3out_object, pod_id, node_id):
        self.pod_id = pod_id
        self.node_id = node_id
        self.node_router_id = details.get("node_router_id")
        self.node_group_policy = details.get("node_group_policy")
        self.node_group_policies = details.get("node_group_policies")
        self.use_router_id_as_loopback = details.get("use_router_id_as_loopback")
        self.node_loopback_ip = details.get("node_loopback_ip")
        self.node = l3out_mso_template.get_l3out_node(l3out_object.details, self.pod_id, self.node_id)
        self.path = "/l3outTemplate/l3outs/{0}/nodes/{1}".format(l3out_object.index, self.node.index if self.node else "-")

    def construct_node_payload(self):
        return delete_none_values(
            {
                # The node group reference is carried by one of two mutually exclusive API attributes,
                # each exposed as its own module option (the modules enforce the mutual exclusivity):
                # - "group"      single reference   <- node_group_policy (str), valid on all supported versions.
                # - "nodeGroups" list of references <- node_group_policies (list), only valid from ND 4.2 onwards.
                # The values are passed through as provided; the API validates them against the running version.
                # On ND 4.2+ the API silently translates a "group" value into a single-element "nodeGroups" and
                # clears "group"; the update path (set_node_replace_ops) compensates for that to stay idempotent.
                "group": self.node_group_policy,
                "nodeGroups": self.node_group_policies,
                "podID": self.pod_id,
                "nodeID": self.node_id,
                "routerID": self.node_router_id,
                "useRouteIDAsLoopback": self.use_router_id_as_loopback,
                "loopbackIPs": [self.node_loopback_ip] if self.node_loopback_ip else None,
            }
        )

    def update_ops(self, ops):
        if self.node:
            self.set_node_replace_ops(ops)
        else:
            self.set_node_add_op(ops)

    def set_node_replace_ops(self, ops):
        remove_data = []
        node_payload = self.construct_node_payload()
        if node_payload.get("useRouteIDAsLoopback") is True or node_payload.get("loopbackIPs") == [""]:
            remove_data.append("loopbackIPs")
        # Updates patch individual attributes against the existing configuration.
        # If the existing node already stores its group reference under "nodeGroups" (ND 4.2+ representation),
        # patching "group" would leave the existing "nodeGroups" untouched and add a conflicting attribute.
        # To keep updating the attribute that already exists, a single "group" value is converted to a
        # one-element "nodeGroups" list; an empty value clears it.
        if self.node.details.get("nodeGroups") and node_payload.get("group") is not None:
            node_payload["nodeGroups"] = [node_payload.pop("group")] if node_payload.get("group") else []
        append_update_ops_data(ops, self.node.details, self.path, node_payload, remove_data)

    def set_node_add_op(self, ops):
        ops.append(self.get_node_add_op())

    def get_node_add_op(self):
        return {"op": "add", "path": self.path, "value": self.construct_node_payload()}

    def get_node_remove_op(self):
        return {"op": "remove", "path": self.path}
