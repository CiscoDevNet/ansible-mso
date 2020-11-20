#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: mso_rest
short_description: Direct access to the Cisco MSO REST API
description:
- Enables the management of the Cisco MSO fabric through direct access to the Cisco MSO REST API.
- This module is not idempotent and does not report changes.
options:
  method:
    description:
    - The HTTP method of the request.
    - Using C(delete) is typically used for deleting objects.
    - Using C(get) is typically used for querying objects.
    - Using C(post) is typically used for modifying objects.
    - Using C(put) is typically used for modifying existing objects.
    - Using C(patch) is typically also used for modifying existing objects.
    type: str
    choices: [ delete, get, post, put, patch ]
    default: get
    aliases: [ action ]
  path:
    description:
    - URI being used to execute API calls.
    type: str
    required: yes
    aliases: [ uri ]
  content:
    description:
    - When used instead of C(src), sets the payload of the API request directly.
    - This may be convenient to template simple requests.
    - For anything complex use the C(template) lookup plugin (see examples)
      or the M(template) module with parameter C(src).
    type: raw
extends_documentation_fragment:
- cisco.mso.modules

notes:
- Certain payloads are known not to be idempotent, so be careful when constructing payloads.
- For JSON payloads nothing special is needed.
- If you do not have any attributes, it may be necessary to add the "attributes" key with an empty dictionnary "{}" for value
  as the MSO does expect the entry to precede any children.
seealso:
- module: cisco.mso.mso_tenant
author:
- Anvitha Jain (@anvitha-jain)
'''

EXAMPLES = r'''
- name: Add tenant
  cisco.mso.mso_rest:
    host: mso
    username: admin
    password: SomeSecretPassword
    path: /api/v1/tenants
    method: post
    content:
      {
          "displayName": "mso_tenant",
          "name": "mso_tenant",
          "description": "",
          "siteAssociations": [],
          "userAssociations": [],
          "_updateVersion": 0
      }
  delegate_to: localhost

- name: Add schema (check_mode)
  cisco.mso.mso_rest:
    host: mso
    username: admin
    password: SomeSecretPassword
    path: /api/v1/schemas
    method: post
    content:
      {
          "displayName": "mso_schema",
          "templates": [{
              "name": "Template_1",
              "tenantId": "{{ add_tenant.jsondata.id }}",
              "displayName": "Template_1",
              "templateSubType": [],
              "templateType": "stretched-template",
              "anps": [],
              "contracts": [],
              "vrfs": [],
              "bds": [],
              "filters": [],
              "externalEpgs": [],
              "serviceGraphs": [],
              "intersiteL3outs": []
          }],
          "sites": [],
          "_updateVersion": 0
      }
  delegate_to: localhost

- name: Query schema
  cisco.mso.mso_rest:
    host: mso
    username: admin
    password: SomeSecretPassword
    path: /api/v1/schemas
    method: get
  delegate_to: localhost
'''

RETURN = r'''
'''

import json
import os

try:
    from ansible.module_utils.six.moves.urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    HAS_URLPARSE = True
except Exception:
    HAS_URLPARSE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text


def update_qsl(url, params):
    ''' Add or update a URL query string '''

    if HAS_URLPARSE:
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urlencode(query)
        return urlunparse(url_parts)
    elif '?' in url:
        return '?' + urlencode(params)
    else:
        return url + '?' + '&'.join(['%s=%s' % (k, v) for k, v in params.items()])


class MSORESTModule(MSOModule):

    def changed(self, d):
        ''' Check MSO response for changes '''

        if isinstance(d, dict):
            for k, v in d.items():
                if k == 'status' and v in ('created', 'modified', 'deleted'):
                    return True
                elif self.changed(v) is True:
                    return True
        elif isinstance(d, list):
            for i in d:
                if self.changed(i) is True:
                    return True

        return False

    def response_type(self, rawoutput, rest_type='json'):
        ''' Handle MSO response output '''

        if rest_type == 'json':
            self.response_json(rawoutput)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        path=dict(type='str', required=True, aliases=['uri']),
        method=dict(type='str', default='get', choices=['delete', 'get', 'post', 'put', 'patch'], aliases=['action']),
        content=dict(type='raw'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    content = module.params.get('content')
    path = module.params.get('path')

    rest_type = 'json'

    mso = MSORESTModule(module)
    mso.result['status'] = -1  # Ensure we always return a status

    # Validate content/payload
    if rest_type == 'json':
        if content and (isinstance(content, dict) or isinstance(content, list)):
            # Validate inline YAML/JSON
            content = json.dumps(content)

    # Perform actual request using auth cookie (Same as mso.request(), but also supports XML)
    if 'port' in mso.params and mso.params.get('port') is not None:
        mso.url = '%(protocol)s://%(host)s:%(port)s/' % mso.params + path.lstrip('/')
    else:
        mso.url = '%(protocol)s://%(host)s/' % mso.params + path.lstrip('/')

    mso.method = mso.params.get('method').upper()

    # Perform request
    resp, info = fetch_url(module, mso.url,
                           data=content,
                           headers=mso.headers,
                           method=mso.method,
                           timeout=mso.params.get('timeout'),
                           use_proxy=mso.params.get('use_proxy'))

    mso.response = info.get('msg')
    mso.status = info.get('status')

    # Report failure
    if info.get('status') not in [200, 201, 202, 204]:
        try:
            # MSO error
            mso.response_type(info['body'], rest_type)
            mso.fail_json(msg='MSO Error %(code)s: %(message)s' % mso.error)
        except KeyError:
            # Connection error
            mso.fail_json(msg='Connection failed for %(url)s. %(msg)s' % info)

    mso.response_type(resp.read(), rest_type)

    if mso.method != 'GET':
        mso.result['changed'] = True

    mso.result['jsondata'] = mso.jsondata

    # Report success
    mso.exit_json(**mso.result)


if __name__ == '__main__':
    main()
