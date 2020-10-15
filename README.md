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

## Update
Getting the latest/nightly collection build

### First Approach
Clone the ansible-mso repository.
```
git clone https://github.com/CiscoDevNet/ansible-mso.git
```

Go to the ansible-mso directory
```
cd ansible-mso
```

Pull the latest master on your mso
```
git pull origin master
```

Build and Install a collection from source
```
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-mso-* --force
```

### Second Approach
Go to: https://github.com/CiscoDevNet/ansible-mso/actions

Select the latest CI build

Under Artifacts download collection and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file
```
ansible-galaxy collection install cisco-mso-1.0.0.tar.gz —-force
```

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco MSO collection repository](https://github.com/CiscoDevNet/ansible-mso/issues).
