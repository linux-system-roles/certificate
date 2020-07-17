from ansible.module_utils.certificate.providers.certmonger import (
    CertificateRequestCertmongerProvider,
)

# fmt: off
PROVIDERS = (
    ("certmonger", CertificateRequestCertmongerProvider),
)
