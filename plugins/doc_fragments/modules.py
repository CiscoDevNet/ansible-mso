# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r'''
options:
  host:
    description:
    - IP Address or hostname of the ACI Multi Site Orchestrator host.
    - If the value is not specified in the task, the value of environment variable C(MSO_HOST) will be used instead.
    type: str
    required: yes
    aliases: [ hostname ]
  port:
    description:
    - Port number to be used for the REST connection.
    - The default value depends on parameter `use_ssl`.
    - If the value is not specified in the task, the value of environment variable C(MSO_PORT) will be used instead.
    type: int
  username:
    description:
    - The username to use for authentication.
    - If the value is not specified in the task, the value of environment variables C(MSO_USERNAME) or C(ANSIBLE_NET_USERNAME) will be used instead.
    type: str
    default: admin
  password:
    description:
    - The password to use for authentication.
    - If the value is not specified in the task, the value of environment variables C(MSO_PASSWORD) or C(ANSIBLE_NET_PASSWORD) will be used instead.
    type: str
    required: yes
  output_level:
    description:
    - Influence the output of this ACI module.
    - C(normal) means the standard output, incl. C(current) dict
    - C(info) adds informational output, incl. C(previous), C(proposed) and C(sent) dicts
    - C(debug) adds debugging output, incl. C(filter_string), C(method), C(response), C(status) and C(url) information
    - If the value is not specified in the task, the value of environment variable C(MSO_OUTPUT_LEVEL) will be used instead.
    type: str
    choices: [ debug, info, normal ]
    default: normal
  timeout:
    description:
    - The socket level timeout in seconds.
    - If the value is not specified in the task, the value of environment variable C(MSO_TIMEOUT) will be used instead.
    type: int
    default: 30
  use_proxy:
    description:
    - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    - If the value is not specified in the task, the value of environment variable C(MSO_USE_PROXY) will be used instead.
    type: bool
    default: yes
  use_ssl:
    description:
    - If C(no), an HTTP connection will be used instead of the default HTTPS connection.
    - If the value is not specified in the task, the value of environment variable C(MSO_USE_SSL) will be used instead.
    type: bool
    default: yes
  validate_certs:
    description:
    - If C(no), SSL certificates will not be validated.
    - This should only set to C(no) when used on personally controlled sites using self-signed certificates.
    - If the value is not specified in the task, the value of environment variable C(MSO_VALIDATE_CERTS) will be used instead.
    type: bool
    default: yes
  login_domain:
    description:
    - The login domain name to use for authentication.
    - The default value is Local.
    - If the value is not specified in the task, the value of environment variable C(MSO_LOGIN_DOMAIN) will be used instead.
    type: str
requirements:
- Multi Site Orchestrator v2.1 or newer
notes:
- Please read the :ref:`aci_guide` for more detailed information on how to manage your ACI infrastructure using Ansible.
- This module was written to support ACI Multi Site Orchestrator v2.1 or newer. Some or all functionality may not work on earlier versions.
'''
