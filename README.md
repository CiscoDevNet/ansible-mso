# ansible-mso

The `ansible-mso` project provides an Ansible collection for managing and automating your Cisco ACI Multi-Site environment.
It consists of a set of modules and roles for performing tasks related to ACI Multi-Site.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

## Requirements
- Ansible v2.8 or newer

## Install
Ansible must be installed
```
sudo pip install ansible
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
