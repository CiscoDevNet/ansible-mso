#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

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
        ''' Handle APIC response output '''

        # self.stdout = str(rawoutput)
        if rest_type == 'json':
            self.response_json(rawoutput)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        path=dict(type='str', required=True, aliases=['uri']),
        method=dict(type='str', default='get', aliases=['action']),
        # method=dict(type='str', default='get', choices=['delete', 'get', 'post'], aliases=['action']),
        src=dict(type='path', aliases=['config_file']),
        content=dict(type='raw'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['content', 'src']],
    )

    content = module.params.get('content')
    path = module.params.get('path')
    src = module.params.get('src')

    # Report missing file
    file_exists = False
    if src:
        if os.path.isfile(src):
            file_exists = True
        else:
            module.fail_json(msg="Cannot find/access src '%s'" % src)

    rest_type = 'json'

    mso = MSORESTModule(module)
    mso.result['status'] = -1  # Ensure we always return a status

    # We include the payload as it may be templated
    payload = content
    if file_exists:
        with open(src, 'r') as config_object:
            # TODO: Would be nice to template this, requires action-plugin
            payload = config_object.read()

    # Perform actual request using auth cookie (Same as mso.request(), but also supports XML)
    if 'port' in mso.params and mso.params.get('port') is not None:
        mso.url = '%(protocol)s://%(host)s:%(port)s/' % mso.params + path.lstrip('/')
    else:
        mso.url = '%(protocol)s://%(host)s/' % mso.params + path.lstrip('/')

    mso.method = mso.params.get('method').upper()

    # Perform request
    resp, info = fetch_url(module, mso.url,
                           data=payload,
                           headers=mso.headers,
                           method=mso.method,
                           timeout=mso.params.get('timeout'),
                           use_proxy=mso.params.get('use_proxy'))

    mso.response = info.get('msg')
    mso.status = info.get('status')

    # Report failure
    if info.get('status') != 200:
        try:
            # APIC error
            mso.response_type(info.get('body'), rest_type)
            mso.fail_json(msg='APIC Error %(code)s: %(text)s' % mso.error)
        except KeyError:
            # Connection error
            mso.fail_json(msg='Connection failed for %(url)s. %(msg)s' % info)

    mso.response_type(resp.read(), rest_type)

    mso.result['jsondata'] = mso.jsondata

    # Report success
    mso.exit_json(**mso.result)


if __name__ == '__main__':
    main()
