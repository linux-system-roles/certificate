#!/usr/bin/python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: certificate_request
short_description: Manage SSL/TLS certificates.
description:
  - "WARNING: Do not use this module directly! It is only for role internal use."
  - The C(certificate_request) module takes a name, desired
    certificate request attributes and certificate properties.
  - The request is generated and sent to the CA to sign.

options:
  name:
    description:
      - Name of the certificate. Can be either a full path
        where files will be stored or a just a simple file name
        to be stored in I(directory).
    required: true
  dns:
    description:
      - Domain (or list of domains) to be included in the
        certificate. Also can provide the default value for
        I(common_name).
    required: false
  ip:
    description:
      - IP (or list of IPs) to be included in the certificate.
        IPs can be IPv4, IPv6 or both. Also can provide the
        default value for I(common_name).
    required: false
  email:
    description:
      - Email (or list of emails) to be included in the
        certificate. Also can provide the default value for
        I(common_name).
    required: false
  owner:
    description:
      - User name (or user id) for the certificate and key files.
    required: false
  group:
    description:
      - Group name (or group id) for the certificate and key files.
    required: false
  common_name:
    description:
      - Common Name requested for the certificate subject.
    required: false
  key_size:
    description:
      - Generate keys with a specific keysize in bits.
    required: false
    default: 2048
  ca:
    description:
      - CA that will issue the certificate. The available options
        will vary depending on each provider.
    required: true
  provider:
    description:
      - The underlying method used to request and manage the
        certificate.
    required: false
    default: certmonger
  directory:
    description:
      - Directory where certificate and key will be stored. Only used
        if I(name) is not an absolute path.
    required: false
    default: /etc/pki/tls
  provider_config_directory:
    description:
      - Directory where pre/post run scripts will be stored.
    required: false
    default: /etc/certmonger
  principal:
    description:
      - Kerberos principal.
    required: false
  key_usage:
    description:
      - Allowed Key Usage for the certificate.
    choices:
      - digitalSignature
      - nonRepudiation
      - keyEncipherment
      - dataEncipherment
      - keyAgreement
      - keyCertSign
      - cRLSign
      - encipherOnly
      - decipherOnly
    required: false
    default:
      - digitalSignature
      - keyEncipherment
  extended_key_usage:
    description:
      - Extended Key Usage attributes to be present in the
        certificate request.
    required: false
    default:
      - id-kp-serverAuth
      - id-kp-clientAuth
  auto_renew:
    description:
      - Indicates if the certificate should be renewed
        automatically before it expires.
    required: false
    default: true
  wait:
    description:
      - If the role should block while waiting for the certificate
        to be issued.
    required: false
    default: true
  country:
    description:
      - Country requested for the certificate subject.
    required: false
  state:
    description:
      - State requested for the certificate subject.
    required: false
  locality:
    description:
      - Locality requested for the certificate subject (usually city).
    required: false
  organization:
    description:
      - Organization requested for the certificate subject.
    required: false
  organizational_unit:
    description:
      - Organizational unit requested for the certificate subject.
    required: false
  contact_email:
    description:
      - Contact email requested for the certificate subject.
    required: false
  run_before:
    description:
      - Command that should run before saving the certificate.
    required: false
  run_after:
    description:
      - Command that should run after saving the certificate.
    required: false
  __header:
    description:
      - Ansible ansible_managed string to put in header of file
      - should be in the format of {{ ansible_managed | comment }}
      - as rendered by the template module
    type: str
    required: true

author:
  - Sergio Oliveira Campos (@seocam)
"""

EXAMPLES = """
# Certificate for single domain
- name: Ensure certificate exists for www.example.com
  certificate_request:
    name: single-example
    dns: www.example.com
    ca: self-sign

# Certificate for multiple domains
- name: Ensure certificate exists for multiple domains
  certificate_request:
    name: many-example
    dns:
      - www.example.com
      - example.com
    ca: self-sign

# Certificate for IPs
- name: Ensure certificate exists for multiple IPs
  certificate_request:
    name: ip-example
    ip:
      - 192.0.2.12
      - 198.51.100.65
      - 2001:db8::2:1
    ca: self-sign

# Certificate for Emails
- name: Ensure certificate exists for multiple Emails
  certificate_request:
    name: email-example
    email:
      - sysadmin@example.com
      - support@example.com
    ca: self-sign

# Choose certificate key size
- name: Ensure key size for certificate is 4096
  certificate_request:
    name: single-example
    dns: www.example.com
    key_size: 4096
    ca: self-sign

# Define certificate owner and group
- name: Ensure user and group for certificate
  certificate_request:
    name: single-example
    dns: www.example.com
    owner: ftp
    group: ftp
    ca: self-sign

# Certificate with Kerberos principal
- name: Ensure certificate exists with principal
  certificate_request:
    name: single-example
    dns: www.example.com
    principal: HTTP/www.example.com@EXAMPLE.com
    ca: self-sign

# Setting key_usage and extended_key_usage
- name: Key with specific values for key_usage and extended_key_usage
  certificate_request:
    name: mycert
    dns: www.example.com
    key_usage:
      - digitalSignature
      - nonRepudiation
      - keyEncipherment
    extended_key_usage:
      - id-kp-clientAuth
      - id-kp-serverAuth
    ca: self-sign

# Don't renew certificate automatically
- name: Issue cert without auto-renew
  certificate_request:
    name: mycert
    dns: www.example.com
    auto_renew: no
    ca: self-sign

# Not wait for certificate to be issued
- name: Ensure certificate exists but don't wait for it
  certificate_request:
    name: single-example
    dns: www.example.com
    wait: no
    ca: self-sign

# Certificate with more subject data
- name: Ensure certificate exists with subject data
  certificate_request:
    name: single-with-subject
    dns: www.example.com
    country: US
    state: NC
    locality: Raleigh
    organization: Red Hat
    organizational_unit: Linux
    contact_email: admin@example.com
    ca: self-sign

# Run commands before and after certificate is issued
- name: Issue cert without auto-renew
  certificate_request:
    name: /tmp/cert-place/mycert
    dns: www.example.com
    run_before: >
      mkdir /tmp/cert-place/
    run_after: >
      touch /tmp/cert-place/certificate_updated
    ca: self-sign
"""

RETURN = ""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.certificate_lsr.providers import providers


KEY_USAGE_CHOICES = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
]

KEY_USAGE_DEFAULTS = [
    "digitalSignature",
    "keyEncipherment",
]

EXTENDED_KEY_USAGE_DEFAULTS = [
    "id-kp-serverAuth",
    "id-kp-clientAuth",
]


class CertificateRequestModule(AnsibleModule):
    """Certificate Request Module.

    This module is responsible for converging SSL/TLS certificates
    using providers.
    """

    def __init__(self, *args, **kwargs):
        argument_spec = kwargs.get("argument_spec", {})
        argument_spec.update(self._get_argument_spec())

        self._provider = None
        super(CertificateRequestModule, self).__init__(argument_spec, *args, **kwargs)

        # Set to True to see logs on the Host machine using `journalctl -f`
        #   TIP: "grep certificate_request" will help you find relevant entries.
        self._debug = False

    @staticmethod
    def _get_argument_spec():
        """Return a dict with the module arguments."""
        return dict(
            name=dict(type="str", required=True),
            dns=dict(type="list"),
            ip=dict(type="list"),
            email=dict(type="list"),
            common_name=dict(type="str"),
            country=dict(type="str"),
            state=dict(type="str"),
            locality=dict(type="str"),
            organization=dict(type="str"),
            organizational_unit=dict(type="str"),
            contact_email=dict(type="str"),
            ca=dict(type="str", required=True),
            directory=dict(type="str", default="/etc/pki/tls"),
            provider_config_directory=dict(type="str", default="/etc/certmonger"),
            provider=dict(type="str", default="certmonger"),
            key_size=dict(type="int", default=2048),
            owner=dict(type="str"),
            group=dict(type="str"),
            principal=dict(type="list"),
            key_usage=dict(
                type="list", choices=KEY_USAGE_CHOICES, default=KEY_USAGE_DEFAULTS
            ),
            extended_key_usage=dict(type="list", default=EXTENDED_KEY_USAGE_DEFAULTS),
            auto_renew=dict(type="bool", default=True),
            wait=dict(type="bool", default=True),
            run_before=dict(type="str"),
            run_after=dict(type="str"),
            __header=dict(type="str"),
        )

    @property
    def provider(self):
        """Instantiate and return the proper provider for the run."""
        if self._provider is None:
            provider_name = self.params.get("provider")
            provider_cls = dict(providers.PROVIDERS).get(provider_name)
            if provider_cls is None:
                self.fail_json(
                    msg="Chosen provider '{0}' is not available.".format(provider_name),
                )
            self._provider = provider_cls(ansible_module=self)

        return self._provider

    def run(self):
        """Run the module using the chosen provider."""
        return self.provider.run(self.check_mode)


def main():
    """Instantiate and execute the Certificate module."""
    CertificateRequestModule(supports_check_mode=True).run()


if __name__ == "__main__":
    main()
