# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from collections import namedtuple

KVPair = namedtuple('KVPair', 'key value')
Item = namedtuple('Item', 'index details')


class MSOSchema:

    def __init__(self, mso_module, schema_name, template_name=None, site_name=None):

        self.mso = mso_module

        schema_id, schema_path, schema = mso_module.query_schema(schema_name)
        self.id = schema_id
        self.path = schema_path
        self.schema = schema

        self.template = self.get_template(template_name) if template_name else None
        self.site = self.get_site(template_name, site_name) if template_name and site_name else None

    def get_object_from_list(self, search_list, kv_list, fail_module):
        """
        Get the first matched object from a list of mso object dictionaries.
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair (Named Tuple)]
        :param fail_module: Value to determine if mso module fail_json function should be triggered. -> Bool
        :return: The index and details of the object. -> Item (Named Tuple)
        """

        def kv_match(kvs, item):
            return all((item.get(kv.key) == kv.value for kv in kvs))

        match = next((Item(index, item) for index, item in enumerate(search_list) if kv_match(kv_list, item)), None)

        if not match and fail_module:
            match_kvs = ["{0}=={1}".format(kv.key, kv.value) for kv in kv_list]
            existing = ["{0}=={1}".format(kv.key, item.get(kv.key)) for item in search_list for kv in kv_list]
            msg = "Provided condition(s) {0} not matching existing object(s): {1}".format(
                match_kvs, ', '.join([
                    str(existing[0 + i: len(match_kvs) + i]) for i in range(0, len(existing), len(match_kvs))]
                ))
            self.mso.fail_json(msg=msg)

        return match

    def get_template(self, template_name, fail_module=True):

        kv_list = [KVPair('name', template_name)]
        return self.get_object_from_list(self.schema.get('templates'), kv_list, fail_module)

    def get_template_bd(self, bd, template, fail_module=True):

        kv_list = [KVPair('name', bd)]
        return self.get_object_from_list(template.get('bds'), kv_list, fail_module)

    def get_site(self, template_name, site_name, fail_module=True):

        if 'sites' not in self.schema:
            msg = "No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template_name)
            self.mso.fail_json(msg=msg)

        kv_list = [KVPair('siteId', self.mso.lookup_site(site_name)), KVPair('templateName', template_name)]
        return self.get_object_from_list(self.schema.get('sites'), kv_list, fail_module)

    def get_site_bd(self, bd, template, site, fail_module=True):

        kv_list = [KVPair('bdRef', self.mso.bd_ref(schema_id=self.id, template=template.get('name'), bd=bd))]
        return self.get_object_from_list(site.get('bds'), kv_list, fail_module)

    def get_site_bd_subnet(self, subnet, site_bd, fail_module=True):

        kv_list = [KVPair('ip', subnet)]
        return self.get_object_from_list(site_bd.get('subnets'), kv_list, fail_module)
