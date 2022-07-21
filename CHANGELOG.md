Changelog
=========

[1.1.6] - 2022-07-19
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- make all tests work with gather_facts: false (#121)

Ensure tests work when using ANSIBLE_GATHERING=explicit

- make min_ansible_version a string in meta/main.yml (#122)

The Ansible developers say that `min_ansible_version` in meta/main.yml
must be a `string` value like `"2.9"`, not a `float` value like `2.9`.

- Add CHANGELOG.md (#123)

[1.1.5] - 2022-05-09
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- tag basic ipa test as a slow test
- bump tox-lsr version to 2.11.0; remove py37; add py310

[1.1.4] - 2022-04-12
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- support setup-snapshot.yml; support set\_vars.yml
- Let each test use a different certificate file name
- Remove the unnecessary code
- bump tox-lsr version to 2.10.1

[1.1.3] - 2022-02-14
--------------------

### New features

- System Roles should consistently use ansible\_managed in configuration files it manages

### Bug fixes

- fix python black errors

### Other Changes

- bump tox-lsr version to 2.9.1

[1.1.2] - 2022-01-11
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- change recursive role symlink to individual role dir symlinks
- bump tox-lsr version to 2.8.3
- Run the new tox test

[1.1.1] - 2021-11-08
--------------------

### New Features

- none

### Bug fixes

- Fix certificate permissions with "group" option
- Fix parser fail on certificate verification.

### Other Changes

- update tox-lsr version to 2.7.1
- support python 39, ansible-core 2.12, ansible-plugin-scan
- support ansible-core 2.11 ansible-test and ansible-lint
- use tox-lsr version 2.5.1

[1.1.0] - 2021-08-10
--------------------

### New features

- Drop support for Ansible 2.8 by bumping the Ansible version to 2.9

### Bug Fixes

- none

### Other Changes

- none

[1.0.5] - 2021-08-06
--------------------

### New features

- Instead of the unarchive module, use "tar" command for backup.

### Bug Fixes

- none

### Other Changes

- none

[1.0.4] - 2021-07-21
--------------------

### New features

- Instead of the archive module, use "tar" command for backup.

### Bug Fixes

- none

### Other Changes

- none

[1.0.3] - 2021-04-13
--------------------

### New Features

- none

### Bug fixes

- Fix some ansible-test sanity errors; suppressing the rest
- Fix ansible-test errors
- Add a note to each module Doc to indicate it is private

### Other Changes

- Remove python-26 environment from tox testing
- update to tox-lsr 2.4.0 - add support for ansible-test sanity with docker
- CI: Add support for RHEL-9

[1.0.2] - 2021-02-12
--------------------

### New features

- support jinja 2.7

### Bug fixes

- Fix centos6 repos; use standard centos images; add centos8
- Workaround for the module\_utils path finding issue in ansible 2.9

### Other Changes

- use tox-lsr 2.2.0
- use molecule v3, drop v2 - use tox-lsr 2.1.2
- Use latest pip.
- remove ansible 2.7 support from molecule
- use tox for ansible-lint instead of molecule
- use github actions instead of travis
- use new tox-lsr plugin
- meta/main.yml: CI add support for all Fedora images

[1.0.1] - 2020-11-12
--------------------

### New Features

- none

### Bug fixes

- Use module\_utils/certificate\_lsr/ to avoid naming conflicts
- Sync collections related changes from template to certificate role
- Fix python black formatting issues

### Other Changes

- lock ansible-lint version at 4.3.5; suppress role name lint warning
- Update version of ansible-freeipa
- Lock ansible-lint on version 4.2.0

[1.0.0] - 2020-08-18
--------------------

### Initial Release
