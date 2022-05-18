# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from collections import namedtuple


class MSOSchema:

    def __init__(self, mso_module, schema_name, template_name=None):

        self.mso = mso_module
        self.template_obj = None
        self.site_obj = None

        schema_id, schema_path, schema_obj = mso_module.query_schema(schema_name)
        self.schema_id = schema_id
        self.schema_path = schema_path
        self.schema_obj = schema_obj

        if template_name:
            self.set_template_object(template_name)

    def set_template_object(self, template):

        self.template_obj = next((
            item for item in self.schema_obj.get('templates') if item.get('name') == template), None)
        if not self.template_obj:
            msg = "Provided template '{0}' does not exist. Existing templates: {1}".format(
                template, ', '.join([t.get('name') for t in self.schema_obj.get('templates')]))
            self.mso.fail_json(msg=msg)

    def get_template_bd_object(self, bd):

        bd_obj = next((
            item for item in self.template_obj.get('bds') if item.get('name') == bd), None)
        if not bd_obj:
            msg = "Provided BD '{0}' does not exist. Existing template BDs: {1}".format(
                bd, ', '.join([b.get('name') for b in self.template_obj.get('bds')]))
            self.mso.fail_json(msg=msg)
        return bd_obj

    def set_site_object(self, site):

        if 'sites' not in self.schema_obj:
            msg = "No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(
                self.template_obj.get('name'))
            self.mso.fail_json(msg=msg)

        site_id = self.mso.lookup_site(site)
        self.site_obj = next((
            item for item in self.schema_obj.get('sites') if
            item.get('siteId') == site_id and item.get('templateName') == self.template_obj.get('name')), None)
        if not self.site_obj:
            msg = "Provided site/template '{0}-{1}' does not exist.".format(site, self.template_obj.get('name'))
            self.mso.fail_json(msg=msg)

    def get_site_bd_object(self, bd, site_obj):
        bd_ref = self.mso.bd_ref(schema_id=self.schema_id, template=self.template_obj.get('name'), bd=bd)
        return next((item for item in site_obj.get('bds') if item.get('bdRef') == bd_ref), None)

    @staticmethod
    def get_site_bd_subnet_object(subnet, bd_site_obj):
        Subnet = namedtuple('Subnet', 'index details')
        return next((Subnet(index, item) for index, item in enumerate(bd_site_obj.get('subnets')) if item.get('ip') == subnet), None)
