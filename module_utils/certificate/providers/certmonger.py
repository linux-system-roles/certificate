import dbus

from .base import CertificateRequestBaseProvider


class CertmongerDBus:
    """Read Certmonger requests information from DBUS."""

    # pylint: disable=too-few-public-methods

    DBUS_CM_PATH = "/org/fedorahosted/certmonger"
    DBUS_CM_IF = "org.fedorahosted.certmonger"
    DBUS_CM_CA_IF = "org.fedorahosted.certmonger.ca"
    DBUS_CM_REQUEST_IF = "org.fedorahosted.certmonger.request"
    DBUS_PROPERTY_IF = "org.freedesktop.DBus.Properties"

    def __init__(self):
        self._sysbus = dbus.SystemBus()
        self._certmonger_bus_obj = self._sysbus.get_object(
            self.DBUS_CM_IF, self.DBUS_CM_PATH
        )

    def _get_ca_name_from_path(self, path):
        ca_bus_obj = self._sysbus.get_object(self.DBUS_CM_IF, path)
        return str(ca_bus_obj.get_nickname(dbus_interface=self.DBUS_CM_CA_IF))

    def _get_request_from_path(self, path):
        request_bus = self._sysbus.get_object(self.DBUS_CM_IF, path)
        request_interface = dbus.Interface(request_bus, self.DBUS_PROPERTY_IF)
        request_properties = request_interface.getAll(self.DBUS_CM_REQUEST_IF)
        ca_path = request_properties.get("ca").replace("requests", "cas")
        request_properties["ca"] = self._get_ca_name_from_path(ca_path)
        return dict(request_properties)

    def get_requests(self):
        """Return a list of Certmonger requests.

        Each Certmonger request is represented in a dict.
        """
        request_paths = self._certmonger_bus_obj.get_requests(
            dbus_interface=self.DBUS_CM_IF
        )
        return [
            self._get_request_from_path(request_path) for request_path in request_paths
        ]


class CertificateRequestCertmongerProvider(CertificateRequestBaseProvider):
    """Certmonger provider for certificate Linux System Role."""

    def __init__(self, *args, **kwargs):
        super(CertificateRequestCertmongerProvider, self).__init__(*args, **kwargs)
        self._certmonger_dbus = CertmongerDBus()
        self._certmonger_metadata = self._get_certmonger_request()

    def _get_certmonger_request(self):
        """Search for certificate metadata in Certmonger using DBUS."""
        for request in self._certmonger_dbus.get_requests():
            if request["cert-file"] == self.certificate_file_path:
                self.module.debug(
                    "Certmonger Metadata for existing certificate: {}".format(request)
                )
                return request
        return {}

    def get_existing_csr_pem_data(self):
        """Read CSR PEM data from certmonger metadata."""
        csr = self._certmonger_metadata.get("csr")
        if not csr:
            return None
        return csr.encode("utf-8")

    def _get_certmonger_ca_from_params(self):
        ca = self.module.params.get("ca")
        if ca == "self-sign":
            ca = "local"
        return ca

    def _get_certmonger_ca_for_existing_cert(self):
        return self._certmonger_metadata.get("ca")

    @property
    def cert_needs_update(self):
        """Check if the existing_certificate needs update.

        Since the provider base class doesn't know about CA this method
        needs to add the verification for CA change.
        """
        needs_update = super(
            CertificateRequestCertmongerProvider, self
        ).cert_needs_update
        ca_from_params = self._get_certmonger_ca_from_params()
        ca_from_existing_cert = self._get_certmonger_ca_for_existing_cert()
        self.module.debug(
            "ca_from_params == ca_from_existing_cert: {}".format(
                ca_from_params == ca_from_existing_cert
            )
        )
        if needs_update or ca_from_params != ca_from_existing_cert:
            return True

        return False

    @property
    def exists_in_certmonger(self):
        """Check if certificate is tracked by certmonger."""
        if self._certmonger_metadata:
            return True
        return False

    def request_certificate(self):
        """Issue or update a certificate using certmonger."""
        # pylint: disable=useless-else-on-loop
        getcert_bin = self.module.get_bin_path("getcert", required=True)
        command = [getcert_bin]

        if self.exists_in_certmonger:
            command += ["resubmit"]
        else:
            command += ["request"]

        # Set common name
        if self.csr.common_name:
            command += ["-N", self.csr.common_name]

        # Set CA
        command += ["-c", self._get_certmonger_ca_from_params()]

        # Wait for cert
        command += ["-w"]

        # Set certificate locations
        if not self.exists_in_certmonger:
            command += ["-k", self.certificate_key_path]
        command += ["-f", self.certificate_file_path]

        # Set Domains
        for dns in self.csr.dns:
            command += ["-D", dns]
        else:
            command += ["-D", ""]

        for ip in self.csr.ip:
            command += ["-A", str(ip)]
        else:
            command += ["-A", ""]

        for email in self.csr.email:
            command += ["-E", email]
        else:
            command += ["-E", ""]

        if not self.exists_in_certmonger:
            # Don't attempt to renew when near to expiration
            command += ["-R"]

        # Set certificate key size
        command += ["-g", str(self.module.params.get("key_size"))]

        self.module.debug("Certmonger command: {}".format(command))

        # Set Kerberos principal
        for principal in self.csr.principal:
            command += ["-K", principal]
        else:
            command += ["-K", ""]

        self._run_command(command, check_rc=True)
        self.changed = True
