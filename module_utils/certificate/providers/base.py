import os
import ipaddress

from abc import ABCMeta, abstractmethod

from pprint import pformat

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from ansible.module_utils import six

if six.PY2:
    FileNotFoundError = IOError  # pylint: disable=redefined-builtin


class CertificateProxy:
    """Proxy class that represents certificate-like objects.

    The CertificateProxy can represent both existing
    certificate and respective CSR and also new certificate
    requests originated from an Ansible module.

    This class only knows about certificate attributes that
    can be useful for idempotency purposes of a certificate.
    """

    def __init__(self, module):
        self.cert_data = {}
        self._x509_obj = None
        self._module = module

    @classmethod
    def load_from_params(cls, module, params):
        """Return a CertificateProxy object initialized from a dict."""
        # pylint: disable=protected-access
        cert_like = cls(module)

        map_attrs = ["dns", "ip", "email"]
        info = {k: v for k, v in params.items() if k in map_attrs}

        info["common_name"] = cert_like._get_common_name_from_params(params)
        if info.get("ip"):
            info["ip"] = [
                ipaddress.ip_address(six.ensure_text(ip)) for ip in info["ip"] if ip
            ]

        cert_like.cert_data = info
        return cert_like

    @staticmethod
    def _get_common_name_from_params(params):
        """Infer the best `common_name` from given parameters.

        If `common_name` is not provided use the first `dns`, `ip` or `email`,
        respectively.
        """
        common_name = params.get("common_name")
        if common_name is None:
            dns = params.get("dns")
            if dns:
                return dns[0]

            ip = params.get("ip")
            if ip:
                return ip[0]

            email = params.get("email")
            if email:
                return email[0]

        return common_name

    @classmethod
    def load_from_pem(cls, module, cert_pem=None, csr_pem=None):
        """Return a CertificateProxy object initialized from PEM data.

        The argument `cert_pem` it's a certificate in PEM format. The argument
        `csr_pem` is a CSR in PEM format.

        If a CSR is provided it has precedence over the certificate itself. The
        reason behind that is that a certificate might not have all attributes
        from the CSR since the CA can choose which attributes to honor. Using the
        certificate as the primary source of information could lead to idempotency
        issues.

        If neither CSR or Certificate are available return None instead.

        """
        # pylint: disable=protected-access
        if csr_pem:
            x509_obj = x509.load_pem_x509_csr(csr_pem, default_backend())
        elif cert_pem:
            x509_obj = x509.load_pem_x509_certificate(cert_pem, default_backend())
        else:
            return None

        cert_like = cls(module)
        cert_like.cert_data = cert_like._get_info_from_x509(x509_obj)
        return cert_like

    def _get_info_from_x509(self, x509_obj):
        info = {}
        if not x509_obj:
            return info

        self._x509_obj = x509_obj

        info["dns"] = self._get_san_values(x509.DNSName)
        info["ip"] = self._get_san_values(x509.IPAddress)
        info["email"] = self._get_san_values(x509.RFC822Name)
        info["common_name"] = self._get_subject_values(NameOID.COMMON_NAME)

        return info

    @property
    def dns(self):
        """Return the DNS(s) in the certificate."""
        return self.cert_data.get("dns") or []

    @property
    def ip(self):
        """Return the IP(s) in the certificate."""
        return self.cert_data.get("ip") or []

    @property
    def email(self):
        """Return the Email(s) in the certificate."""
        return self.cert_data.get("email") or []

    @property
    def common_name(self):
        """Return the certificate common_name."""
        return self.cert_data.get("common_name")

    def _get_subject_values(self, oid):
        values = self._x509_obj.subject.get_attributes_for_oid(oid)
        if values:
            return values[0].value
        return None

    def _get_san_values(self, san_type):
        if not self._subject_alternative_names:
            return []
        return self._subject_alternative_names.value.get_values_for_type(san_type)

    @property
    def _subject_alternative_names(self):
        try:
            san = self._x509_obj.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
        except x509.ExtensionNotFound:
            return []
        return san

    def __eq__(self, other):
        """Compare two instances of CertificateProxy for idempotency purposes."""
        # TODO: compare CA here
        #   Currently each provider is responsible for implementing the CA
        #   comparison.
        if not isinstance(other, CertificateProxy):
            raise TypeError(
                "Cannot compare 'CertificateProxy' with '{}'".format(type(other),)
            )

        self._module.debug(
            "Preparing CertificateProxy objects for comparison: "
            "some keys might be added and/or removed."
        )
        self._module.debug("Original A: {}".format(pformat(self.cert_data)))
        self._module.debug("Original B: {}".format(pformat(other.cert_data)))

        # Remove empty sequences and strings, false and None values
        #   before comparison happens
        self_info = {k: v for k, v in self.cert_data.items() if v}
        other_info = {k: v for k, v in other.cert_data.items() if v}

        self._module.debug("Comparing CertificateProxy objects:")
        self._module.debug("A: {}".format(pformat(self_info)))
        self._module.debug("B: {}".format(pformat(other_info)))

        equals = self_info == other_info
        self._module.debug("A == B: {}".format(equals))
        return equals

    def __ne__(self, other):
        """Verify if two CertificateProxy objects are different."""
        return not self == other


class CertificateRequestBaseProvider:
    """Base class for Certificate Request Providers."""

    certificate_proxy_class = CertificateProxy

    __metaclass__ = ABCMeta

    def __init__(self, ansible_module):
        self.module = ansible_module
        self.message = ""
        self.changed = False

        self._existing_certificate = None
        self._csr = None

    def _run_command(self, *args, **kwargs):
        """Proxy run_command from Ansible module.

        This is a utility method and does not change the original method
        in anyway.
        """
        return self.module.run_command(*args, **kwargs)

    def _get_store_location(self, key=False):
        if key:
            ext = ".key"
            subdir = "private"
        else:
            ext = ".crt"
            subdir = "certs"

        name = self.module.params.get("name")
        if os.path.isabs(name):
            return name + ext

        if os.sep in name:
            self.module.fail_json(
                msg=(
                    "Relative path '{}' not allowed for 'name' parameter (use "
                    "either a simple string or an absolute path)."
                ).format(name)
            )

        base_path = self.module.params.get("directory")
        return os.path.join(base_path, subdir, (name + ext),)

    @property
    def existing_certificate(self):
        """Instance CertificateProxy for the current certificate.

        If no CSR or Certificate are currently available, return None instead.
        """
        if self._existing_certificate is None:
            if not os.path.exists(self.certificate_file_path):
                self._existing_certificate = False
            else:
                csr_pem = self.get_existing_csr_pem_data()
                cert_pem = self.get_existing_certificate_pem_data()

                self._existing_certificate = self.certificate_proxy_class.load_from_pem(
                    self.module, cert_pem, csr_pem,
                )
        return self._existing_certificate

    @property
    def csr(self):
        """Instance CertificateProxy for the new certificate request."""
        if self._csr is None:
            self._csr = self.certificate_proxy_class.load_from_params(
                self.module, self.module.params,
            )
        return self._csr

    @property
    def certificate_file_path(self):
        """Path where certificate should be placed."""
        return self._get_store_location()

    @property
    def certificate_key_path(self):
        """Path where key should be placed."""
        return self._get_store_location(key=True)

    @property
    def cert_needs_update(self):
        """Verify if the existing certificate needs to be updated."""
        return self.existing_certificate != self.csr

    def _exit_success(self):
        self.module.exit_json(
            changed=self.changed, msg=self.message,
        )

    def _set_user_and_group_if_different(self):
        file_attrs = {
            "path": self.certificate_file_path,
            "owner": self.module.params.get("owner"),
            "group": self.module.params.get("group"),
            "mode": None,
            "attributes": None,
            "secontext": [],
        }
        cert_diff = {}
        self.changed = self.module.set_fs_attributes_if_different(
            file_attrs, self.changed, cert_diff,
        )
        self.module.debug("Certificate fs attribute diff: {}".format(cert_diff))

        file_attrs["path"] = self.certificate_key_path
        key_diff = {}
        self.changed = self.module.set_fs_attributes_if_different(
            file_attrs, self.changed, key_diff,
        )
        self.module.debug("Certificate Key fs attribute diff: {}".format(key_diff))

        return cert_diff or key_diff

    def run(self, check_mode=False):
        """Entry point for the providers called from the actual Ansible module."""
        if check_mode:
            self.message += "(Check mode) "

        issue_or_update_cert = False
        self.message += "Certificate "
        if not self.existing_certificate:
            self.message += "requested (new)."
            issue_or_update_cert = True
        else:
            if self.cert_needs_update:
                self.message += "requested (update)."
                issue_or_update_cert = True
            else:
                self.message += "is up-to-date."

        if issue_or_update_cert and not check_mode:
            self.request_certificate()

        updated_fs_attrs = self._set_user_and_group_if_different()
        if updated_fs_attrs:
            self.message += " File attributes updated."
        self._exit_success()

    def get_existing_certificate_pem_data(self):
        """Read the PEM data for a certificate from it's file.

        If certificate file is not available return False.
        """
        try:
            with open(self.certificate_file_path, "r") as cert_file:
                return cert_file.read().encode("utf-8")
        except FileNotFoundError:
            return False

    @abstractmethod
    def get_existing_csr_pem_data(self):
        """Read the PEM data for a CSR.

        Must be implemented by the provider.
        """
        raise NotImplementedError

    @abstractmethod
    def request_certificate(self):
        """Issues a new certificate or updates an existing certificate.

        Must be implemented by the provider.
        """
        raise NotImplementedError
