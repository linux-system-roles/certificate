from ansible.module_utils.certificate_lsr.providers import certmonger


# fmt: off
PROVIDERS = (
    ("certmonger", certmonger.CertificateRequestCertmongerProvider),
)
