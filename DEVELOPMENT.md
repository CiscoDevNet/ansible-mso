# Development Guide

This guide defines the expected structure for integration tests in the
`cisco.mso` collection. Use it when adding tests for a new module or cleaning
up an existing target.

## Module creation

TODO: document the standard process for creating a module, including argument
specification, module documentation, examples, idempotency, version support,
and the corresponding integration-test target.

## Integration-test targets

Each module test is stored in
`tests/integration/targets/<module_name>/tasks/main.yml`. Add an `aliases` file
for every integration-test target. The `unsupported` entry is an
`ansible-test` marker for the test target; it does not describe the module's
support status. Keep the marker commented while the target is supported:

```text
# The module and integration test are supported.
# Uncomment the following line to exclude this test target when necessary.
# unsupported
```

When the target is not currently runnable, activate the marker and document the
reason:

```text
# The module is supported, but this integration test is not currently run
# because <required environment or feature> is unavailable.
unsupported
```

Keep test-specific exceptions documented next to the affected target.

## Test setup

Validate the connection variables and define shared connection data and test
fixtures once at the top of the test. Use target-specific variables first,
generic variables second, and a static default last. For example:

```yaml
- name: Test that required variables are defined
  ansible.builtin.fail:
    msg: 'Please define mso_hostname, mso_username and mso_password.'
  when: >-
    mso_hostname is not defined or
    mso_username is not defined or
    mso_password is not defined

- name: Set test connection and fixture variables
  ansible.builtin.set_fact:
    mso_info: &mso_info
      host: '{{ mso_hostname }}'
      username: '{{ mso_username }}'
      password: '{{ mso_password }}'
      validate_certs: '{{ mso_validate_certs | default(false) }}'
      use_ssl: '{{ mso_use_ssl | default(true) }}'
      use_proxy: '{{ mso_use_proxy | default(true) }}'
      output_level: debug
    mso_test:
      schema: '{{ mso_schema_example | default(mso_schema | default("ansible_test")) }}'
      template: Template1
      attribute_name: attribute_value
```

Replace `example` with the target-specific variable name. Keep the specific
override, generic override, and static default when all three levels are
needed by the target.

## Version-specific behavior

Query the controller version once when the test contains version-dependent
behavior. Use a version-gated block when the complete test applies only to a
specific controller version; this allows the condition to bypass the entire
test, including its clean-environment tasks. Keep the test lifecycle in an
`Exercise <module_name>` block with an `always` section so cleanup runs when
that exercise starts and later fails. Use a task-level condition for an
individual feature within the version-gated block:

```yaml
- name: Query controller version
  cisco.mso.mso_version:
    <<: *mso_info
    state: query
  register: version

- name: Run tests supported from ND v4.1 (NDO v5.1)
  when: version.current.version is version('5.1', '>=')
  block:
    - name: Exercise <module_name>
      block:
        # CLEAN ENVIRONMENT
        - name: Remove the version-dependent test object before testing
          cisco.mso.<module_name>:
            <<: *mso_info
            name: versioned_object_name
            state: absent

        - name: Test feature supported from ND v4.2 (NDO v5.2)
          cisco.mso.<module_name>:
            <<: *mso_info
            name: versioned_object_name
          when: version.current.version is version('5.2', '>=')

      always:
        # CLEANUP
```

Use a version condition only around functionality that is genuinely
unsupported on that version. A version exclusion may bypass the complete
version-gated exercise, but must not hide unrelated setup, assertions, or
cleanup for tests that are otherwise supported. Explain the version-specific
behavior in a comment or task name, using both product versions where relevant.

## Pre-existing objects

Some tests require objects that must already exist in the test environment. Do
not create or query those objects as part of the target when the API or test
contract makes them prerequisites. State the reason in a comment, for example:

```yaml
# Due to API changes in ND 4.2, the configured site and tenant are prerequisites
# for this test and must already exist. They are intentionally not created or
# queried here.
- name: Associate the pre-existing site with the test schema template
  cisco.mso.mso_schema_site:
    <<: *mso_info
    schema: '{{ mso_test.schema }}'
    site: '{{ mso_test.site }}'
    template: '{{ mso_test.template }}'
```

The example uses the existing site without attempting to manage the site or
tenant themselves.

## Test block and cleanup

Put the test lifecycle in an enclosing `block`. When version-dependent
behavior is present, query the controller version before the version-gated
block, as shown in [Version-specific behavior](#version-specific-behavior).
The version-gated block may skip the complete exercise, including its
clean-environment tasks. The clean-environment setup should be the first task
in the `Exercise <module_name>` block. Keep cleanup in that block's `always`
section so it runs when the exercise starts and later fails. If the surrounding
version-gated block is skipped, the exercise and its cleanup are not run:

```yaml
- name: Exercise <module_name>
  block:
    # CLEAN ENVIRONMENT
    - name: Remove the test object before testing
      cisco.mso.<module_name>:
        <<: *mso_info
        name: '{{ mso_test.name }}'
        state: absent

    # CREATE, UPDATE, QUERY, DELETE, and ERROR HANDLING sections follow here.

  always:
    # CLEANUP
    - name: Remove the test object even when a test fails
      cisco.mso.<module_name>:
        <<: *mso_info
        name: '{{ mso_test.name }}'
        state: absent
```

## General test conventions

Apply these conventions to all integration-test tasks unless the module's
documented behavior requires an exception:

- Use descriptive task and fixture names that explain the scenario, such as
  `Create subnet 1 with defaults`.
- Use documented module defaults instead of repeating default values in
  ordinary tasks. For example, when `state: present` is the module default,
  omit it from ordinary setup and create tasks. Specify a default explicitly
  only when testing required arguments or another state-dependent behavior.
- When a module or ND defines a default, include a scenario that omits the
  attribute and assert the effective value returned by the module. Module
  defaults can be asserted in check mode and after the normal operation. ND
  defaults should be verified after the normal operation or a subsequent
  query, because the controller applies them.
- Exercise every supported operation of the module under test in check mode,
  including query and query-all operations when supported, and assert the
  expected result. Supporting fixture creation tasks do not need separate
  check-mode coverage when the same operation is already covered by a
  lifecycle scenario.
- Verify idempotency for mutating operations by repeating the operation and
  asserting that the repeated task is not changed. The initial lifecycle task
  provides check-mode coverage; do not repeat the idempotency task in check
  mode unless check mode has distinct behavior that needs separate coverage.
- Assert all relevant returned attributes for every applicable result, not only
  the result of the initial create operation. Assert empty results after
  deletion where the module provides them.
- Add separate scenarios only when they cover a meaningful input or behavior
  variation. Avoid duplicate scenarios that do not increase coverage.
- Create only the prerequisites needed by the lifecycle under test. Do not
  attempt to manage objects that are documented as pre-existing prerequisites;
  document those requirements in the test as described in [Pre-existing
  objects](#pre-existing-objects).

## Create

For each supported creation scenario, test check mode, the normal operation,
and idempotency. Assert every relevant attribute, including module- or
ND-defined defaults:

The initial create result may contain only the payload produced by the module,
while a repeated create or later query may include additional
controller-generated attributes. Assert the managed attributes individually
when comparing create and idempotency results so these different response
shapes do not cause a false failure.

```yaml
- name: Create object in check mode
  cisco.mso.<module_name>: &object_present
    <<: *mso_info
    name: '{{ mso_test.name }}'
    description: Initial object
  check_mode: true
  register: cm_create_object

- name: Create object
  cisco.mso.<module_name>:
    <<: *object_present
  register: nm_create_object

- name: Create object again
  cisco.mso.<module_name>:
    <<: *object_present
  register: nm_create_object_again

- name: Verify create and idempotency
  ansible.builtin.assert:
    that:
      - cm_create_object is changed
      - nm_create_object is changed
      - nm_create_object_again is not changed
      - cm_create_object.current.name == nm_create_object.current.name == mso_test.name
      - cm_create_object.current.description == nm_create_object.current.description == 'Initial object'
```

## Update

Update all supported mutable attributes. Assert all relevant current attributes
for the check-mode result, normal result, and idempotent repeat. Use full
current-object comparisons when the response shape is stable; otherwise assert
each managed attribute individually. When the module updates a parent object or
replaces a complete nested collection, also verify that unspecified attributes
and child objects are preserved. The child may be managed by a separate module
and may not be exposed as an attribute of the parent module. A separate
sibling-preservation check is not needed merely because the managed object
belongs to a collection; it applies when the update can replace the parent or
complete collection. For a nested collection, use an existing later query to
compare an unaffected sibling with
its pre-update result instead of adding another query. Parent references outside
the module's returned object only need separate verification when preserving
them is part of the module's contract:

```yaml
- name: Update all mutable attributes in check mode
  cisco.mso.<module_name>: &object_updated
    <<: *object_present
    description: Updated object
  check_mode: true
  register: cm_update_object

- name: Update all mutable attributes
  cisco.mso.<module_name>:
    <<: *object_updated
  register: nm_update_object

- name: Update object again
  cisco.mso.<module_name>:
    <<: *object_updated
  register: nm_update_object_again

- name: Verify update, idempotency, and preservation
  ansible.builtin.assert:
    that:
      - cm_update_object is changed
      - nm_update_object is changed
      - nm_update_object_again is not changed
      - cm_update_object.current.name == nm_update_object.current.name == mso_test.name
      - cm_update_object.current.description == nm_update_object.current.description == 'Updated object'
      # Assert every other supported attribute in each result. For nested
      # resources, also assert that unspecified attributes and child objects
      # remain unchanged.
```

### Preserve child objects during parent updates

When a module updates a parent object that contains child objects managed by a
separate module, or replaces a complete nested collection, and child
preservation is part of its contract, create or define at least one child with
the child module before updating the parent. The parent module does not need to
expose the child's attributes. Update only the parent-managed attributes; do not
manage the child as part of that parent update. After the normal update, query
the child directly or use a later child query already present in the test. A
successful query confirms that the child still exists; a missing child causes
the query to fail. Do not rely only on the parent response, because the child
may not be included there even when it was preserved. Repeat the parent update
to verify idempotency as usual. Do not apply this check merely because the
target object is one member of a collection; a module that updates only the
selected child should verify that child's managed attributes instead.

This catches a PATCH behavior where the request sends only the updated parent
object. The controller can treat that object as a replacement and remove
children that were not included in the request. This is a known issue in some
older modules; affected modules have already been identified and tracked for
future fixes. Keep the direct child query in the test so the behavior is
visible until the module is corrected.

```yaml
- name: Create child object with its dedicated module before updating the parent
  cisco.mso.<child_module>:
    <<: *child_present
  register: nm_create_child

- name: Update parent without managing the child object
  cisco.mso.<parent_module>: &parent_updated
    <<: *parent_present
    description: Updated parent
  register: nm_update_parent

- name: Query child after parent update
  cisco.mso.<child_module>:
    <<: *child_query
    state: query
```

## Query

Query an individual object when supported. Run the query in check mode as well
and assert all returned attributes:

```yaml
- name: Query an individual object in check mode
  cisco.mso.<module_name>: &object_query
    <<: *object_present
    state: query
  check_mode: true
  register: cm_query_object

- name: Query an individual object
  cisco.mso.<module_name>:
    <<: *object_query
  register: nm_query_object

- name: Verify individual query
  ansible.builtin.assert:
    that:
      - cm_query_object is not changed
      - nm_query_object is not changed
      - cm_query_object.current.name == nm_query_object.current.name == mso_test.name
      - cm_query_object.current.description == nm_query_object.current.description == 'Initial object'
```

## Query all

The object created by the preceding lifecycle also belongs to the queried
collection and counts toward the result. Create one additional object
specifically for the collection query in normal mode; separate check-mode
fixture creation is not needed when check mode is already covered by the
lifecycle scenarios. Then assert a collection length greater than one, compare
the check-mode and normal collections, and verify each expected object is
present:

```yaml
- name: Create query-all object 1
  cisco.mso.<module_name>:
    <<: *mso_info
    name: query_all_object_1

- name: Query all objects in check mode
  cisco.mso.<module_name>: &query_all
    <<: *mso_info
    state: query
  check_mode: true
  register: cm_query_all_objects

- name: Query all objects
  cisco.mso.<module_name>:
    <<: *query_all
  register: nm_query_all_objects

- name: Verify collection query
  ansible.builtin.assert:
    that:
      - cm_query_all_objects is not changed
      - nm_query_all_objects is not changed
      - cm_query_all_objects.current == nm_query_all_objects.current
      - cm_query_all_objects.current | length > 1
      - cm_query_all_objects.current | selectattr('name', 'equalto', mso_test.name) | list | length == 1
      - cm_query_all_objects.current | selectattr('name', 'equalto', 'query_all_object_1') | list | length == 1
```

The direct collection comparison verifies the complete returned objects, while
the membership assertions make the expected collection contents explicit. Do
not add query-all coverage for a module whose API does not support it.

## Delete

Verify check mode, normal deletion, absence through repeated deletion, and
idempotency. Assert the complete prior object and that the proposed/current
results are empty after deletion:

```yaml
- name: Delete object in check mode
  cisco.mso.<module_name>:
    <<: *object_present
    state: absent
  check_mode: true
  register: cm_delete_object

- name: Delete object
  cisco.mso.<module_name>:
    <<: *object_present
    state: absent
  register: nm_delete_object

- name: Delete object again
  cisco.mso.<module_name>:
    <<: *object_present
    state: absent
  register: nm_delete_object_again

- name: Verify delete, absence, and idempotency
  ansible.builtin.assert:
    that:
      - cm_delete_object is changed
      - nm_delete_object is changed
      - cm_delete_object.previous.name == nm_delete_object.previous.name == mso_test.name
      - cm_delete_object.proposed == cm_delete_object.current == {}
      - nm_delete_object.proposed == nm_delete_object.current == {}
      - nm_delete_object_again is not changed
      - nm_delete_object_again.previous == nm_delete_object_again.proposed == nm_delete_object_again.current == {}
```

## Error handling

Keep all expected error cases together after the lifecycle sections. Cover
errors raised by the module and by Ansible argument-spec validation, including
`required_if`, required values, invalid choices, and invalid object references.
Register expected failures and assert both failure status and the relevant
message:

```yaml
# ERROR HANDLING
- name: Reject a missing required attribute in check mode
  cisco.mso.<module_name>:
    <<: *mso_info
    name: MissingAttributeObject
    state: present
  check_mode: true
  register: cm_missing_required
  ignore_errors: true

- name: Reject an invalid module argument in check mode
  cisco.mso.<module_name>:
    <<: *mso_info
    name: InvalidObject
    mode: invalid
  check_mode: true
  register: cm_invalid_argument
  ignore_errors: true

- name: Verify argument-spec and module error handling
  ansible.builtin.assert:
    that:
      - cm_missing_required is failed
      - cm_missing_required.msg is search('missing required arguments')
      - cm_invalid_argument is failed
      - cm_invalid_argument.msg is search('value of mode must be one of')
```

For a `required_if` condition, include the triggering state explicitly and
assert the complete validation message. Include a case for each distinct
triggering state, for example:

```yaml
- name: Reject present without subnet
  cisco.mso.mso_schema_template_anp_epg_subnet:
    <<: *mso_info
    schema: '{{ mso_test.schema }}'
    template: '{{ mso_test.template }}'
    anp: '{{ mso_test.anp }}'
    epg: '{{ mso_test.epg }}'
    state: present
  check_mode: true
  register: cm_missing_subnet
  ignore_errors: true

- name: Verify required-if validation
  ansible.builtin.assert:
    that:
      - cm_missing_subnet is failed
      - cm_missing_subnet.msg is search('state is present but all of the following are missing: subnet')
```

## Validation

Before submitting a test change:

- Run [`ansible-test sanity`](https://docs.ansible.com/projects/ansible/latest/dev_guide/testing_sanity.html)
  for module and documentation changes.
- Run the targeted
  [`ansible-test network-integration`](https://docs.ansible.com/projects/ansible/latest/network/dev_guide/developing_resource_modules_network.html)
  target when access to the integration lab is available.
- Confirm that cleanup runs on both successful and failing test paths.
