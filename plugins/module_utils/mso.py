# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
import re
from ansible.module_utils.basic import json
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import filterfalse
from ansible.module_utils.six.moves.urllib.parse import urlencode, urljoin
from ansible.module_utils.urls import fetch_url


if PY3:
    def cmp(a, b):
        return (a > b) - (a < b)


def issubset(subset, superset):
    ''' Recurse through nested dictionary and compare entries '''

    # Both objects are the same object
    if subset is superset:
        return True

    # Both objects are identical
    if subset == superset:
        return True

    # Both objects have a different type
    if type(subset) != type(superset):
        return False

    for key, value in subset.items():
        # Ignore empty values
        if value is None:
            return True

        # Item from subset is missing from superset
        if key not in superset:
            return False

        # Item has different types in subset and superset
        if type(superset.get(key)) != type(value):
            return False

        # Compare if item values are subset
        if isinstance(value, dict):
            if not issubset(superset.get(key), value):
                return False
        elif isinstance(value, list):
            try:
                # NOTE: Fails for lists of dicts
                if not set(value) <= set(superset.get(key)):
                    return False
            except TypeError:
                # Fall back to exact comparison for lists of dicts
                diff = list(filterfalse(lambda i: i in value, superset.get(key))) + list(filterfalse(lambda j: j in superset.get(key), value))
                if diff:
                    return False
        elif isinstance(value, set):
            if not value <= superset.get(key):
                return False
        else:
            if not value == superset.get(key):
                return False

    return True


def update_qs(params):
    ''' Append key-value pairs to self.filter_string '''
    accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
    return '?' + urlencode(accepted_params)


def mso_argument_spec():
    return dict(
        host=dict(type='str', required=True, aliases=['hostname'], fallback=(env_fallback, ['MSO_HOST'])),
        port=dict(type='int', required=False, fallback=(env_fallback, ['MSO_PORT'])),
        username=dict(type='str', default='admin', fallback=(env_fallback, ['MSO_USERNAME', 'ANSIBLE_NET_USERNAME'])),
        password=dict(type='str', required=True, no_log=True, fallback=(env_fallback, ['MSO_PASSWORD', 'ANSIBLE_NET_PASSWORD'])),
        output_level=dict(type='str', default='normal', choices=['debug', 'info', 'normal'], fallback=(env_fallback, ['MSO_OUTPUT_LEVEL'])),
        timeout=dict(type='int', default=30, fallback=(env_fallback, ['MSO_TIMEOUT'])),
        use_proxy=dict(type='bool', default=True, fallback=(env_fallback, ['MSO_USE_PROXY'])),
        use_ssl=dict(type='bool', default=True, fallback=(env_fallback, ['MSO_USE_SSL'])),
        validate_certs=dict(type='bool', default=True, fallback=(env_fallback, ['MSO_VALIDATE_CERTS'])),
        login_domain=dict(type='str', fallback=(env_fallback, ['MSO_LOGIN_DOMAIN'])),
    )


def mso_reference_spec():
    return dict(
        name=dict(type='str', required=True),
        schema=dict(type='str'),
        template=dict(type='str'),
    )


def mso_subnet_spec():
    return dict(
        subnet=dict(type='str', required=True, aliases=['ip']),
        description=dict(type='str'),
        scope=dict(type='str', default='private', choices=['private', 'public']),
        shared=dict(type='bool', default=False),
        no_default_gateway=dict(type='bool', default=False),
        querier=dict(type='bool', default=False),
    )


def mso_dhcp_spec():
    return dict(
        dhcp_option_policy=dict(type='dict', option=mso_dhcp_option_spec()),
        name=dict(type='str', required=True),
        version=dict(type='int', required=True),
    )


def mso_dhcp_option_spec():
    return dict(
        name=dict(type='str', required=True),
        version=dict(type='int', required=True),
    )


def mso_contractref_spec():
    return dict(
        name=dict(type='str', required=True),
        schema=dict(type='str'),
        template=dict(type='str'),
        type=dict(type='str', required=True, choices=['consumer', 'provider']),
    )


def mso_expression_spec():
    return dict(
        type=dict(type='str', required=True, aliases=['tag']),
        operator=dict(type='str', choices=['not_in', 'in', 'equals', 'not_equals', 'has_key', 'does_not_have_key'], required=True),
        value=dict(type='str'),
    )


def mso_expression_spec_ext_epg():
    return dict(
        type=dict(type='str', choices=['ip_address'], required=True),
        operator=dict(type='str', choices=['equals'], required=True),
        value=dict(type='str', required=True),
    )


def mso_hub_network_spec():
    return dict(
        name=dict(type='str', required=True),
        tenant=dict(type='str', required=True),
    )


class MSOModule(object):

    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = {'Content-Type': 'text/json'}

        # normal output
        self.existing = dict()

        # info output
        self.previous = dict()
        self.proposed = dict()
        self.sent = dict()
        self.stdout = None

        # debug output
        self.has_modified = False
        self.filter_string = ''
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None

        # Ensure protocol is set
        self.params['protocol'] = 'https' if self.params.get('use_ssl', True) else 'http'

        # Set base_uri
        if self.params.get('port') is not None:
            self.baseuri = '{protocol}://{host}:{port}/api/v1/'.format(**self.params)
        else:
            self.baseuri = '{protocol}://{host}/api/v1/'.format(**self.params)

        if self.module._debug:
            self.module.warn('Enable debug output because ANSIBLE_DEBUG was set.')
            self.params['output_level'] = 'debug'

        if self.params.get('password'):
            # Perform password-based authentication, log on using password
            self.login()
        else:
            self.module.fail_json(msg="Parameter 'password' is required for authentication")

    def get_login_domain_id(self, domain):
        ''' Get a domain and return its id '''
        if domain is None:
            return domain
        d = self.get_obj('auth/login-domains', key='domains', name=domain)
        if not d:
            self.module.fail_json(msg="Login domain '%s' is not a valid domain name." % domain)
        if 'id' not in d:
            self.module.fail_json(msg="Login domain lookup failed for domain '%s': %s" % (domain, d))
        return d['id']

    def login(self):
        ''' Log in to MSO '''

        # Perform login request
        if (self.params.get('login_domain') is not None) and (self.params.get('login_domain') != 'Local'):
            domain_id = self.get_login_domain_id(self.params.get('login_domain'))
            payload = {'username': self.params.get('username'), 'password': self.params.get('password'), 'domainId': domain_id}
        else:
            payload = {'username': self.params.get('username'), 'password': self.params.get('password')}
        self.url = urljoin(self.baseuri, 'auth/login')
        resp, auth = fetch_url(self.module,
                               self.url,
                               data=json.dumps(payload),
                               method='POST',
                               headers=self.headers,
                               timeout=self.params.get('timeout'),
                               use_proxy=self.params.get('use_proxy'))

        # Handle MSO response
        if auth.get('status') != 201:
            self.response = auth.get('msg')
            self.status = auth.get('status')
            self.fail_json(msg='Authentication failed: {msg}'.format(**auth))

        payload = json.loads(resp.read())

        self.headers['Authorization'] = 'Bearer {token}'.format(**payload)

    def request(self, path, method=None, data=None, qs=None):
        ''' Generic HTTP method for MSO requests. '''
        self.path = path

        if method is not None:
            self.method = method

        # If we PATCH with empty operations, return
        if method == 'PATCH' and not data:
            return {}

        self.url = urljoin(self.baseuri, path)

        if qs is not None:
            self.url = self.url + update_qs(qs)

        resp, info = fetch_url(self.module,
                               self.url,
                               headers=self.headers,
                               data=json.dumps(data),
                               method=self.method,
                               timeout=self.params.get('timeout'),
                               use_proxy=self.params.get('use_proxy'),
                               )
        self.response = info.get('msg')
        self.status = info.get('status')

        # self.result['info'] = info

        # Get change status from HTTP headers
        if 'modified' in info:
            self.has_modified = True
            if info.get('modified') == 'false':
                self.result['changed'] = False
            elif info.get('modified') == 'true':
                self.result['changed'] = True

        # 200: OK, 201: Created, 202: Accepted, 204: No Content
        if self.status in (200, 201, 202, 204):
            output = resp.read()
            if output:
                return json.loads(output)

        # 404: Not Found
        elif self.method == 'DELETE' and self.status == 404:
            return {}

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status >= 400:
            try:
                output = resp.read()
                payload = json.loads(output)
            except (ValueError, AttributeError):
                try:
                    payload = json.loads(info.get('body'))
                except Exception:
                    self.fail_json(msg='MSO Error:', data=data, info=info)
            if 'code' in payload:
                self.fail_json(msg='MSO Error {code}: {message}'.format(**payload), data=data, info=info, payload=payload)
            else:
                self.fail_json(msg='MSO Error:'.format(**payload), data=data, info=info, payload=payload)

        return {}

    def query_objs(self, path, key=None, **kwargs):
        ''' Query the MSO REST API for objects in a path '''
        found = []
        objs = self.request(path, method='GET')

        if objs == {}:
            return found

        if key is None:
            key = path

        if key not in objs:
            self.fail_json(msg="Key '%s' missing from data", data=objs)

        for obj in objs.get(key):
            for kw_key, kw_value in kwargs.items():
                if kw_value is None:
                    continue
                if obj.get(kw_key) != kw_value:
                    break
            else:
                found.append(obj)
        return found

    def query_obj(self, path, **kwargs):
        ''' Query the MSO REST API for the whole object at a path '''
        obj = self.request(path, method='GET')
        if obj == {}:
            return {}
        for kw_key, kw_value in kwargs.items():
            if kw_value is None:
                continue
            if obj.get(kw_key) != kw_value:
                return {}
        return obj

    def get_obj(self, path, **kwargs):
        ''' Get a specific object from a set of MSO REST objects '''
        objs = self.query_objs(path, **kwargs)
        if len(objs) == 0:
            return {}
        if len(objs) > 1:
            self.fail_json(msg='More than one object matches unique filter: {0}'.format(kwargs))
        return objs[0]

    def lookup_schema(self, schema):
        ''' Look up schema and return its id '''
        if schema is None:
            return schema

        s = self.get_obj('schemas', displayName=schema)
        if not s:
            self.module.fail_json(msg="Schema '%s' is not a valid schema name." % schema)
        if 'id' not in s:
            self.module.fail_json(msg="Schema lookup failed for schema '%s': %s" % (schema, s))
        return s.get('id')

    def lookup_domain(self, domain):
        ''' Look up a domain and return its id '''
        if domain is None:
            return domain

        d = self.get_obj('auth/domains', key='domains', name=domain)
        if not d:
            self.module.fail_json(msg="Domain '%s' is not a valid domain name." % domain)
        if 'id' not in d:
            self.module.fail_json(msg="Domain lookup failed for domain '%s': %s" % (domain, d))
        return d.get('id')

    def lookup_roles(self, roles):
        ''' Look up roles and return their ids '''
        if roles is None:
            return roles

        ids = []
        for role in roles:
            name = role
            access_type = "readWrite"
            if 'name' in role:
                name = role.get('name')
                if role.get('access_type') == 'read':
                    access_type = 'readOnly'
            r = self.get_obj('roles', name=name)
            if not r:
                self.module.fail_json(msg="Role '%s' is not a valid role name." % name)
            if 'id' not in r:
                self.module.fail_json(msg="Role lookup failed for role '%s': %s" % (name, r))
            ids.append(dict(roleId=r.get('id'), accessType=access_type))
        return ids

    def lookup_site(self, site):
        ''' Look up a site and return its id '''
        if site is None:
            return site

        s = self.get_obj('sites', name=site)
        if not s:
            self.module.fail_json(msg="Site '%s' is not a valid site name." % site)
        if 'id' not in s:
            self.module.fail_json(msg="Site lookup failed for site '%s': %s" % (site, s))
        return s.get('id')

    def lookup_sites(self, sites):
        ''' Look up sites and return their ids '''
        if sites is None:
            return sites

        ids = []
        for site in sites:
            s = self.get_obj('sites', name=site)
            if not s:
                self.module.fail_json(msg="Site '%s' is not a valid site name." % site)
            if 'id' not in s:
                self.module.fail_json(msg="Site lookup failed for site '%s': %s" % (site, s))
            ids.append(dict(siteId=s.get('id'), securityDomains=[]))
        return ids

    def lookup_tenant(self, tenant):
        ''' Look up a tenant and return its id '''
        if tenant is None:
            return tenant

        t = self.get_obj('tenants', key='tenants', name=tenant)
        if not t:
            self.module.fail_json(msg="Tenant '%s' is not valid tenant name." % tenant)
        if 'id' not in t:
            self.module.fail_json(msg="Tenant lookup failed for tenant '%s': %s" % (tenant, t))
        return t.get('id')

    def lookup_remote_location(self, remote_location):
        ''' Look up a remote location and return its path and id '''
        if remote_location is None:
            return None

        remote = self.get_obj('platform/remote-locations', key='remoteLocations', name=remote_location)
        if 'id' not in remote:
            self.module.fail_json(msg="No remote location found for remote '%s'" % (remote_location))
        remote_info = dict(id=remote.get('id'), path=remote.get('credential')['remotePath'])
        return remote_info

    def lookup_users(self, users):
        ''' Look up users and return their ids '''
        # Ensure tenant has at least admin user
        if users is None:
            return [dict(userId="0000ffff0000000000000020")]

        ids = []
        for user in users:
            u = self.get_obj('users', username=user)
            if not u:
                self.module.fail_json(msg="User '%s' is not a valid user name." % user)
            if 'id' not in u:
                self.module.fail_json(msg="User lookup failed for user '%s': %s" % (user, u))
            id = dict(userId=u.get('id'))
            if id in ids:
                self.module.fail_json(msg="User '%s' is duplicate." % user)
            ids.append(id)

        if 'admin' not in users:
            ids.append(dict(userId="0000ffff0000000000000020"))
        return ids

    def create_label(self, label, label_type):
        ''' Create a new label '''
        return self.request('labels', method='POST', data=dict(displayName=label, type=label_type))

    def lookup_labels(self, labels, label_type):
        ''' Look up labels and return their ids (create if necessary) '''
        if labels is None:
            return None

        ids = []
        for label in labels:
            label_obj = self.get_obj('labels', displayName=label)
            if not label_obj:
                label_obj = self.create_label(label, label_type)
            if 'id' not in label_obj:
                self.module.fail_json(msg="Label lookup failed for label '%s': %s" % (label, label_obj))
            ids.append(label_obj.get('id'))
        return ids

    def anp_ref(self, **data):
        ''' Create anpRef string '''
        return '/schemas/{schema_id}/templates/{template}/anps/{anp}'.format(**data)

    def epg_ref(self, **data):
        ''' Create epgRef string '''
        return '/schemas/{schema_id}/templates/{template}/anps/{anp}/epgs/{epg}'.format(**data)

    def bd_ref(self, **data):
        ''' Create bdRef string '''
        return '/schemas/{schema_id}/templates/{template}/bds/{bd}'.format(**data)

    def contract_ref(self, **data):
        ''' Create contractRef string '''
        # Support the contract argspec
        if 'name' in data:
            data['contract'] = data.get('name')
        return '/schemas/{schema_id}/templates/{template}/contracts/{contract}'.format(**data)

    def filter_ref(self, **data):
        ''' Create a filterRef string '''
        return '/schemas/{schema_id}/templates/{template}/filters/{filter}'.format(**data)

    def vrf_ref(self, **data):
        ''' Create vrfRef string '''
        return '/schemas/{schema_id}/templates/{template}/vrfs/{vrf}'.format(**data)

    def ext_epg_ref(self, **data):
        ''' Create extEpgRef string '''
        return '/schemas/{schema_id}/templates/{template}/externalEpgs/{external_epg}'.format(**data)

    def vrf_dict_from_ref(self, data):
        vrf_ref_regex = re.compile(r'\/schemas\/(.*)\/templates\/(.*)\/vrfs\/(.*)')
        vrf_dict = vrf_ref_regex.search(data)
        return {
            'vrfName': vrf_dict.group(3),
            'schemaId': vrf_dict.group(1),
            'templateName': vrf_dict.group(2),
        }

    def dict_from_ref(self, data):
        if data and data != '':
            ref_regex = re.compile(r'\/schemas\/(.*)\/templates\/(.*)\/(.*)\/(.*)')
            dic = ref_regex.search(data)
            if dic is not None:
                schema_id = dic.group(1)
                template_name = dic.group(2)
                category = dic.group(3)
                name = dic.group(4)
                uri_map = {
                    'vrfs': ['vrfName', 'schemaId', 'templateName'],
                    'bds': ['bdName', 'schemaId', 'templateName'],
                    'filters': ['filterName', 'schemaId', 'templateName'],
                    'contracts': ['contractName', 'schemaId', 'templateName'],
                    'l3outs': ['l3outName', 'schemaId', 'templateName'],
                    'anps': ['anpName', 'schemaId', 'templateName'],
                }
                result = {
                    uri_map[category][0]: name,
                    uri_map[category][1]: schema_id,
                    uri_map[category][2]: template_name,
                }
                return result
            else:
                self.module.fail_json(msg="There was no group in search: {data}".format(data=data))

    def make_reference(self, data, reftype, schema_id, template):
        ''' Create a reference from a dictionary '''
        # Removes entry from payload
        if data is None:
            return None

        if data.get('schema') is not None:
            schema_obj = self.get_obj('schemas', displayName=data.get('schema'))
            if not schema_obj:
                self.fail_json(msg="Referenced schema '{schema}' in {reftype}ref does not exist".format(reftype=reftype, **data))
            schema_id = schema_obj.get('id')

        if data.get('template') is not None:
            template = data.get('template')

        refname = '%sName' % reftype

        return {
            refname: data.get('name'),
            'schemaId': schema_id,
            'templateName': template,
        }

    def make_subnets(self, data):
        ''' Create a subnets list from input '''
        if data is None:
            return None

        subnets = []
        for subnet in data:
            if 'subnet' in subnet:
                subnet['ip'] = subnet.get('subnet')
            if subnet.get('description') is None:
                subnet['description'] = subnet.get('subnet')
            subnets.append(dict(
                ip=subnet.get('ip'),
                description=str(subnet.get('description')),
                scope=subnet.get('scope'),
                shared=subnet.get('shared'),
                noDefaultGateway=subnet.get('no_default_gateway'),
                querier=subnet.get('querier'),
            ))

        return subnets

    def make_dhcp_label(self, data):
        ''' Create a DHCP policy from input '''
        if data is None:
            return None
        if data and 'dhcp_option_policy' in data:
            data['dhcpOptionLabel'] = data.get('dhcp_option_policy')
            del data['dhcp_option_policy']
        return data

    def sanitize(self, updates, collate=False, required=None, unwanted=None):
        ''' Clean up unset keys from a request payload '''
        if required is None:
            required = []
        if unwanted is None:
            unwanted = []
        self.proposed = deepcopy(self.existing)
        self.sent = deepcopy(self.existing)

        for key in self.existing:
            # Remove References
            if key.endswith('Ref'):
                del(self.proposed[key])
                del(self.sent[key])
                continue

            # Removed unwanted keys
            elif key in unwanted:
                del(self.proposed[key])
                del(self.sent[key])
                continue

        # Clean up self.sent
        for key in updates:
            # Always retain 'id'
            if key in required:
                pass

            # Remove unspecified values
            elif not collate and updates.get(key) is None:
                if key in self.existing:
                    del(self.sent[key])
                continue

            # Remove identical values
            elif not collate and updates.get(key) == self.existing.get(key):
                del(self.sent[key])
                continue

            # Add everything else
            if updates.get(key) is not None:
                self.sent[key] = updates.get(key)

        # Update self.proposed
        self.proposed.update(self.sent)

    def exit_json(self, **kwargs):
        ''' Custom written method to exit from module. '''

        if self.params.get('state') in ('absent', 'present'):
            if self.params.get('output_level') in ('debug', 'info'):
                self.result['previous'] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result['changed'] = True
        if self.stdout:
            self.result['stdout'] = self.stdout

        # Return the gory details when we need it
        if self.params.get('output_level') == 'debug':
            self.result['method'] = self.method
            self.result['response'] = self.response
            self.result['status'] = self.status
            self.result['url'] = self.url

            if self.params.get('state') in ('absent', 'present'):
                self.result['sent'] = self.sent
                self.result['proposed'] = self.proposed

        self.result['current'] = self.existing

        if self.module._diff and self.result.get('changed') is True:
            self.result['diff'] = dict(
                before=self.previous,
                after=self.existing,
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        ''' Custom written method to return info on failure. '''

        if self.params.get('state') in ('absent', 'present'):
            if self.params.get('output_level') in ('debug', 'info'):
                self.result['previous'] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result['changed'] = True
            if self.stdout:
                self.result['stdout'] = self.stdout

        # Return the gory details when we need it
        if self.params.get('output_level') == 'debug':
            if self.url is not None:
                self.result['method'] = self.method
                self.result['response'] = self.response
                self.result['status'] = self.status
                self.result['url'] = self.url

            if self.params.get('state') in ('absent', 'present'):
                self.result['sent'] = self.sent
                self.result['proposed'] = self.proposed

        self.result['current'] = self.existing

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def check_changed(self):
        ''' Check if changed by comparing new values from existing'''
        existing = self.existing
        if 'password' in existing:
            existing['password'] = self.sent.get('password')
        return not issubset(self.sent, existing)

    def update_filter_obj(self, contract_obj, filter_obj, filter_type, contract_display_name=None, updateFilterRef=True):
        ''' update filter with more information '''
        if updateFilterRef:
            filter_obj['filterRef'] = self.dict_from_ref(filter_obj.get('filterRef'))
        if contract_display_name:
            filter_obj['displayName'] = contract_display_name
        else:
            filter_obj['displayName'] = contract_obj.get('displayName')
        filter_obj['filterType'] = filter_type
        filter_obj['contractScope'] = contract_obj.get('scope')
        filter_obj['contractFilterType'] = contract_obj.get('filterType')
        return filter_obj
