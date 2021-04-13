# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from distutils.version import StrictVersion

import dbus

from ansible.module_utils.certificate_lsr.providers import base


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


class CertificateRequestCertmongerProvider(base.CertificateRequestBaseProvider):
    """Certmonger provider for certificate Linux System Role."""

    def __init__(self, *args, **kwargs):
        super(CertificateRequestCertmongerProvider, self).__init__(*args, **kwargs)
        self._certmonger_dbus = CertmongerDBus()
        self._certmonger_metadata = self._get_certmonger_request()
        self._version = None

    @property
    def certmonger_version(self):
        """Return the certmonger version (the first found in PATH)."""
        if self._version is None:
            certmonger_bin = self.module.get_bin_path("certmonger", required=True)
            certmonger_version_cmd = [certmonger_bin, "--version"]
            ret, out, err = self._run_command(certmonger_version_cmd, check_rc=False)
            if ret == 0 and not err:
                version_str = out.split(" ")[1]
                self._version = StrictVersion(version_str)
            else:
                self.module.fail_json(
                    msg="Could not get certmonger version using '{0}'".format(
                        " ".join(certmonger_version_cmd),
                    )
                )

        return self._version

    def module_input_validation(self):
        """Validate module input."""
        principal = self.module.params.get("principal") or []
        ca = self.module.params.get("ca")

        # 'IPA' CA requires principal to be set
        if ca.lower() == "ipa" and not principal:
            self.module.fail_json(
                msg=("Principal parameter is mandatory for 'ipa' CA.")
            )

        # Validate principal format
        for single_principal in principal:
            try:
                primary, instance_realm = single_principal.split("/")
                instance, realm = instance_realm.split("@")
            except ValueError:
                invalid_principal = True
            else:
                invalid_principal = False

            if invalid_principal or not all([primary, instance, realm]):
                self.module.fail_json(
                    msg=(
                        "Invalid principal '{0}'. It should be formatted as "
                        "'primary/instance@REALM'".format(single_principal)
                    )
                )

    def _get_certmonger_request(self):
        """Search for certificate metadata in Certmonger using DBUS."""
        for request in self._certmonger_dbus.get_requests():
            if request["cert-file"] == self.certificate_file_path:
                self.module.debug(
                    "Certmonger Metadata for existing certificate: {0}".format(request)
                )
                return request
        return {}

    def get_existing_csr_pem_data(self):
        """Read CSR PEM data from certmonger metadata."""
        csr = self._certmonger_metadata.get("csr")
        if not csr:
            return None
        return csr.encode("utf-8")

    def get_existing_certificate_auto_renew_flag(self):
        """Check if the existing certificate is configured for auto renew."""
        return bool(int(self._certmonger_metadata.get("autorenew", "0")))

    def _get_certmonger_ca_from_params(self):
        ca = self.module.params.get("ca")
        if ca == "self-sign":
            ca = "local"
        elif ca.upper() == "IPA":
            ca = "IPA"
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
            "ca_from_params == ca_from_existing_cert: {0}".format(
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

    def set_auto_renew(self, auto_renew):
        """Set the auto_renew flag using the appropriate getcert command."""
        if not self.exists_in_certmonger:
            # When creating a new cert just set the auto/no-auto renew param
            if auto_renew:
                command = ["-r"]
            else:
                command = ["-R"]
            return command

        # If certificate exists in certmonger it will require a different
        #   command to update the auto_renew flag
        getcert_bin = self.module.get_bin_path("getcert", required=True)
        track_command = [
            getcert_bin,
            "start-tracking",
            "-f",
            self.certificate_file_path,
        ]
        if auto_renew:
            track_command += ["-r"]
        else:
            track_command += ["-R"]
        self._run_command(track_command, check_rc=True)

        return []

    def _set_user_and_group_if_different(self):
        if self.module.params.get("wait"):
            return super(
                CertificateRequestCertmongerProvider,
                self,
            )._set_user_and_group_if_different()

        if self.module.params.get("owner") or self.module.params.get("group"):
            self.module.fail_json(
                msg=(
                    "Cannot set 'owner' or 'group' when "
                    "'wait=no' and provider='certmonger'."
                )
            )

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
        if self.csr.subject:
            command += ["-N", self.csr.subject]

        # Set CA
        command += ["-c", self._get_certmonger_ca_from_params()]

        # Wait for cert if required
        if self.module.params["wait"]:
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

        # Set auto_renew
        command += self.set_auto_renew(self.csr.auto_renew)

        # Set certificate key size
        allow_key_size_update = self.certmonger_version >= StrictVersion("0.79.0")
        if not self.exists_in_certmonger or allow_key_size_update:
            command += ["-g", str(self.module.params.get("key_size"))]

        self.module.debug("Certmonger command: {0}".format(command))

        # Set Kerberos principal
        for principal in self.csr.principal:
            command += ["-K", principal]
        else:
            command += ["-K", ""]

        # Set key_usage
        for key_usage in self.csr.key_usage:
            command += ["-u", key_usage]

        # Set extended_key_usage
        for extended_key_usage in self.csr.extended_key_usage:
            command += ["-U", extended_key_usage]
        else:
            command += ["-U", ""]

        if self.module.params.get("run_before"):
            command += ["-B", self.pre_run_script_path]
        else:
            command += ["-B", ""]

        if self.module.params.get("run_after"):
            command += ["-C", self.post_run_script_path]
        else:
            command += ["-C", ""]

        self._run_command(command, check_rc=True)
        self.changed = True
