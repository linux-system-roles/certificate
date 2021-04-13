# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.certificate_lsr.providers import certmonger


# fmt: off
PROVIDERS = (
    ("certmonger", certmonger.CertificateRequestCertmongerProvider),
)
