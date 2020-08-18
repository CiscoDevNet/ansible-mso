# ansible-mso

The `ansible-mso` project provides an Ansible collection for managing and automating your Cisco ACI Multi-Site environment.
It consists of a set of modules and roles for performing tasks related to ACI Multi-Site.

This collection has been tested and supports MSO 2.1+.
Modules supporting new features introduced in MSO API in specific MSO versions might not be supported in earlier MSO releases.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
- Ansible v2.9 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
```

Install the collection
```
ansible-galaxy collection install cisco.mso
```
## Use
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.
```yaml
- hosts: mso
  gather_facts: no

  tasks:
  - name: Add a new site EPG
    cisco.mso.mso_schema_site_anp_epg:
      host: mso_host
      username: admin
      password: SomeSecretPassword
      schema: Schema1
      site: Site1
      template: Template1
      anp: ANP1
      epg: EPG1
      state: present
    delegate_to: localhost
```
### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco MSO collection repository](https://github.com/CiscoDevNet/ansible-mso/issues).
