Changelog
=========

[1.3.6] - 2024-07-02
--------------------

### Bug Fixes

- fix: add support for EL10 (#229)

### Other Changes

- ci: ansible-lint action now requires absolute directory (#228)

[1.3.5] - 2024-06-11
--------------------

### Other Changes

- ci: use tox-lsr 3.3.0 which uses ansible-test 2.17 (#223)
- ci: tox-lsr 3.4.0 - fix py27 tests; move other checks to py310 (#225)
- ci: Add supported_ansible_also to .ansible-lint (#226)

[1.3.4] - 2024-04-04
--------------------

### Other Changes

- ci: bump codecov/codecov-action from 3 to 4 (#217)
- ci: fix python unit test - copy pytest config to tests/unit (#218)
- ci: bump ansible/ansible-lint from 6 to 24 (#219)
- ci: bump mathieudutour/github-tag-action from 6.1 to 6.2 (#220)
- chore: Add spetrosi as a code owner (#221)

[1.3.3] - 2024-01-16
--------------------

### Other Changes

- ci: Use supported ansible-lint action; run ansible-lint against the collection (#210)
- ci: bump github/codeql-action from 2 to 3 (#211)
- ci: bump actions/setup-python from 4 to 5 (#212)
- ci: Use supported ansible-lint action; run ansible-lint against the collection (#213)

[1.3.2] - 2023-12-08
--------------------

### Other Changes

- ci: bump actions/github-script from 6 to 7 (#207)
- refactor: get_ostree_data.sh use env shebang - remove from .sanity* (#208)

[1.3.1] - 2023-11-22
--------------------

### Other Changes

- refactor: improve support for ostree systems (#205)

[1.3.0] - 2023-10-26
--------------------

### New Features

- feat: support for ostree systems (#203)

### Other Changes

- build(deps): bump actions/checkout from 3 to 4 (#194)
- ci: ensure dependabot git commit message conforms to commitlint (#198)
- ci: use dump_packages.py callback to get packages used by role (#200)
- ci: tox-lsr version 3.1.1 (#202)

[1.2.2] - 2023-09-08
--------------------

### Other Changes

- ci: Add markdownlint, test_html_build, and build_docs workflows (#190)

  - markdownlint runs against README.md to avoid any issues with
    converting it to HTML
  - test_converting_readme converts README.md > HTML and uploads this test
    artifact to ensure that conversion works fine
  - build_docs converts README.md > HTML and pushes the result to the
    docs branch to publish dosc to GitHub pages site.
  - Fix markdown issues in README.md
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

- docs: Make badges consistent, run markdownlint on all .md files (#191)

  - Consistently generate badges for GH workflows in README RHELPLAN-146921
  - Run markdownlint on all .md files
  - Add custom-woke-action if not used already
  - Rename woke action to Woke for a pretty badge

- ci: Remove badges from README.md prior to converting to HTML (#192)

  - Remove thematic break after badges
  - Remove badges from README.md prior to converting to HTML
  
  Signed-off-by: Sergei Petrosian <spetrosi@redhat.com>

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
