from ansible.module_utils.certificate_lsr.providers.certmonger import (
    CertificateRequestCertmongerProvider,
)

# fmt: off
PROVIDERS = (
    ("certmonger", CertificateRequestCertmongerProvider),
)
