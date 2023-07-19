Changelog
=========

[1.2.1] - 2023-07-19
--------------------

### Bug Fixes

- fix: Re-issue certificate if key size changes (#188)
- fix: facts being gathered unnecessarily (#187)

### Other Changes

- ci: ansible-lint - ignore var-naming[no-role-prefix] (#185)
- ci: ansible-test ignores file for ansible-core 2.15 (#186)

[1.2.0] - 2023-07-07
--------------------

### New Features

- feat: Allow setting certificate and key files mode (#175)

### Other Changes

- ci: Use Ubuntu repository for Python 2.7 (#179)
- ci: Remove certreader dependency (#180)
- test: Update pre-commit hooks (#181)
- ci: Remove package installation through pip (#182)
- tests: Ensure ipaserver hostname is a FQDN (#183)

[1.1.13] - 2023-06-23
--------------------

### Other Changes

- ci: Add pull request template and run commitlint on PR title only (#174)
- ci: Rename commitlint to PR title Lint, echo PR titles from env var (#176)
- test: easily generate certs for tests for other roles (#177)

[1.1.12] - 2023-05-26
--------------------

### Other Changes

- docs: Consistent contributing.md for all roles - allow role specific contributing.md section
- docs: remove unused Dependencies section in README

[1.1.11] - 2023-04-27
--------------------

### Other Changes

- test: check generated files for ansible_managed, fingerprint (#165)
- ci: Add commitlint GitHub action to ensure conventional commits with feedback

[1.1.10] - 2023-04-06
--------------------

### Other Changes

- Add README-ansible.md to refer Ansible intro page on linux-system-roles.github.io (#162)
- Fingerprint RHEL System Role managed config files (#163)

[1.1.9] - 2023-02-02
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- Fix assert in tests_run_hooks.yml (#157)

[1.1.8] - 2023-01-20
--------------------

### New Features

- none

### Bug Fixes

- ansible-lint 6.x fixes

### Other Changes

- Add check for non-inclusive language (#142)
- Cleanup non-inclusive words
- ignore files for ansible-test 2.13 and 2.14 (#149)

[1.1.7] - 2022-09-19
--------------------

### New Features

- none

### Bug Fixes

- Move Debian to Python 3 packages

The python 2 packages don't exist any more in current stable Debian 11
and Ubuntu 22.04 LTS. Use the python3-* packages (vars/main.yml has the
correct ones).

### Other Changes

- changelog_to_tag action - github action ansible test improvements

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

- Fix some ansible-test errors; suppressing the rest
- Fix ansible-test errors
- Add a note to each module Doc to indicate it is private

### Other Changes

- Remove python-26 environment from tox testing
- update to tox-lsr 2.4.0 - add support for ansible-test with docker
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
