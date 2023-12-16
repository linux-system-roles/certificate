# -*- coding: utf-8 -*-

# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import os
import traceback

try:
    import ipaddress
except ImportError:
    HAS_IPADDRESS = False
    IPADDRESS_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_IPADDRESS = True
    IPADDRESS_IMPORT_ERROR = None

from abc import ABCMeta, abstractmethod

from pprint import pformat


# for ansible-test import/compile functionality
def fake_func(*args, **kwargs):
    return None


class FakeSubClass(object):
    def __init__(self, *args):
        pass

    def __getattr__(self, value):
        if value == "subtype":
            return fake_func
        else:
            return object


class FakeBaseClass(object):
    def __getattr__(self, value):
        if value == "oid":
            return FakeBaseClass()
        elif value.endswith("OID"):
            return FakeSubClass()
        else:
            return FakeSubClass


# for ansible-test import/compile functionality


try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ObjectIdentifier
except ImportError:
    HAS_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_IMPORT_ERROR = traceback.format_exc()
    x509 = FakeBaseClass()
    ANY_EXTENDED_KEY_USAGE = None
    IPSEC_END_SYSTEM = None
    IPSEC_TUNNEL = None
    IPSEC_USER = None
else:
    HAS_CRYPTOGRAPHY = True
    CRYPTOGRAPHY_IMPORT_ERROR = None
    ANY_EXTENDED_KEY_USAGE = ObjectIdentifier("2.5.29.37.0")
    IPSEC_END_SYSTEM = ObjectIdentifier("1.3.6.1.5.5.7.3.5")
    IPSEC_TUNNEL = ObjectIdentifier("1.3.6.1.5.5.7.3.6")
    IPSEC_USER = ObjectIdentifier("1.3.6.1.5.5.7.3.7")

try:
    from pyasn1.codec.der import decoder
    from pyasn1.type import char, namedtype, tag, univ
except ImportError:
    HAS_PYASN1 = False
    PYASN1_IMPORT_ERROR = traceback.format_exc()
    univ = FakeBaseClass()
    namedtype = FakeBaseClass()
    tag = FakeBaseClass()
    char = FakeBaseClass()
else:
    HAS_PYASN1 = True
    PYASN1_IMPORT_ERROR = None

from ansible.module_utils.six import PY2
from ansible.module_utils._text import to_bytes, to_text

if PY2:
    FileNotFoundError = IOError  # pylint: disable=redefined-builtin


def _escape_dn_value(val):
    """Escape special characters in RFC4514 Distinguished Name value."""
    if not val:
        return ""

    # See https://tools.ietf.org/html/rfc4514#section-2.4
    val = val.replace("\\", "\\\\")
    val = val.replace('"', '\\"')
    val = val.replace("+", "\\+")
    val = val.replace(",", "\\,")
    val = val.replace(";", "\\;")
    val = val.replace("<", "\\<")
    val = val.replace(">", "\\>")
    val = val.replace("\0", "\\00")

    if val[0] in ("#", " "):
        val = "\\" + val
    if val[-1] == " ":
        val = val[:-1] + "\\ "

    return val


class _PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "name-type",
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "name-string",
            univ.SequenceOf(char.GeneralString()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class _KRB5PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "realm",
            char.GeneralString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "principalName",
            _PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class KRB5PrincipalName(x509.OtherName):
    """Kerberos Principal x509 OtherName implementation."""

    # pylint: disable=too-few-public-methods

    oid = "1.3.6.1.5.2.2"

    def __init__(self, type_id, value):
        super(KRB5PrincipalName, self).__init__(type_id, value)
        self.name = self._decode_krb5principalname(value)

    @staticmethod
    def _decode_krb5principalname(data):
        # pylint: disable=unsubscriptable-object
        principal = decoder.decode(data, asn1Spec=_KRB5PrincipalName())[0]
        realm = to_text(
            str(principal["realm"]).replace("\\", "\\\\").replace("@", "\\@")
        )
        name = principal["principalName"]["name-string"]
        name = "/".join(
            to_text(str(n))
            .replace("\\", "\\\\")
            .replace("/", "\\/")
            .replace("@", "\\@")
            for n in name
        )
        name = "%s@%s" % (name, realm)
        return name


class CertificateProxy:
    """Proxy class that represents certificate-like objects.

    The CertificateProxy can represent both existing
    certificate and respective CSR and also new certificate
    requests originated from an Ansible module.

    This class only knows about certificate attributes that
    can be useful for idempotency purposes of a certificate.
    """

    EXTENDED_KEY_USAGES_OID_MAP = {
        "id-kp-serverAuth": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        "id-kp-clientAuth": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        "id-kp-codeSigning": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        "id-kp-emailProtection": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "id-kp-timeStamping": x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
        "id-kp-OCSPSigning": x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
        "anyExtendedKeyUsage": ANY_EXTENDED_KEY_USAGE,
        "id-kp-ipsecEndSystem": IPSEC_END_SYSTEM,
        "id-kp-ipsecTunnel": IPSEC_TUNNEL,
        "id-kp-ipsecUser": IPSEC_USER,
    }

    KEY_USAGE_ATTR_MAP = {
        "digital_signature": "digitalSignature",
        "content_commitment": "nonRepudiation",
        "key_encipherment": "keyEncipherment",
        "data_encipherment": "dataEncipherment",
        "key_agreement": "keyAgreement",
        "key_cert_sign": "keyCertSign",
        "crl_sign": "cRLSign",
        "encipher_only": "encipherOnly",
        "decipher_only": "decipherOnly",
    }

    SUBJECT_SHORT_PARAM_MAP = {
        "country": "C",
        "state": "ST",
        "locality": "L",
        "organization": "O",
        "organizational_unit": "OU",
        "contact_email": "emailAddress",
        "common_name": "CN",
    }

    def __init__(self, module):
        self.cert_data = {}
        self._x509_obj = None
        self._module = module

    @classmethod
    def load_from_params(cls, module, params):
        """Return a CertificateProxy object initialized from a dict."""
        # pylint: disable=protected-access
        cert_like = cls(module)

        map_attrs = [
            "dns",
            "ip",
            "email",
            "key_usage",
            "extended_key_usage",
            "principal",
            "auto_renew",
            "key_size",
        ]
        info = {k: v for k, v in params.items() if k in map_attrs}

        info["subject"] = cls._get_subject_from_params(params)
        if info.get("ip"):
            info["ip"] = [ipaddress.ip_address(to_text(ip)) for ip in info["ip"] if ip]

        if info.get("key_usage"):
            info["key_usage"] = set(info["key_usage"])

        if info.get("extended_key_usage"):
            info["extended_key_usage"] = [
                cls._get_extended_key_usage_object_identifier(eku).dotted_string
                for eku in info["extended_key_usage"]
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
    def load_from_pem(cls, module, cert_pem=None, csr_pem=None, auto_renew=False):
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
        info = cert_like._get_info_from_x509(x509_obj)
        info["auto_renew"] = auto_renew
        info["key_size"] = x509_obj.public_key().key_size
        cert_like.cert_data = info
        return cert_like

    def _get_info_from_x509(self, x509_obj):
        info = {}
        if not x509_obj:
            return info

        self._x509_obj = x509_obj

        info["dns"] = self._get_san_values(x509.DNSName)
        info["ip"] = self._get_san_values(x509.IPAddress)
        info["email"] = self._get_san_values(x509.RFC822Name)
        info["principal"] = self._get_san_values(x509.OtherName, KRB5PrincipalName)
        info["key_usage"] = self._get_key_usage()
        info["extended_key_usage"] = self._get_extended_key_usage()
        info["subject"] = self._get_subject_from_x509()
        return info

    @classmethod
    def _get_subject_from_params(cls, params):
        subject = {k: v for k, v in params.items() if k in cls.SUBJECT_SHORT_PARAM_MAP}
        subject["common_name"] = cls._get_common_name_from_params(params)
        return cls._format_subject(**subject)

    @classmethod
    def _format_subject(cls, **kwargs):
        # Ideally we should be using cryptography.x509.Name.rfc4514_string()
        #   but since the method is only available for cryptography >= 2.5,
        #   we are building the string manually using _escape_dn_value.
        subject = []
        for param_name, short_name in cls.SUBJECT_SHORT_PARAM_MAP.items():
            value = kwargs.get(param_name)
            if value:
                subject.append("{0}={1}".format(short_name, _escape_dn_value(value)))
        return ",".join(subject)

    def _get_subject_from_x509(self):
        subject = {
            "country": self._get_subject_values(NameOID.COUNTRY_NAME),
            "state": self._get_subject_values(NameOID.STATE_OR_PROVINCE_NAME),
            "locality": self._get_subject_values(NameOID.LOCALITY_NAME),
            "organization": self._get_subject_values(NameOID.ORGANIZATION_NAME),
            "organizational_unit": self._get_subject_values(
                NameOID.ORGANIZATIONAL_UNIT_NAME
            ),
            "contact_email": self._get_subject_values(NameOID.EMAIL_ADDRESS),
            "common_name": self._get_subject_values(NameOID.COMMON_NAME),
        }
        return self._format_subject(**subject)

    @property
    def auto_renew(self):
        """Return the auto_renew flag for the certificate."""
        return self.cert_data.get("auto_renew") or False

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
    def key_usage(self):
        """Return the Key Usage in the certificate."""
        return self.cert_data.get("key_usage") or set()

    @property
    def extended_key_usage(self):
        """Return the Extended Key Usage in the certificate."""
        return self.cert_data.get("extended_key_usage") or []

    @property
    def common_name(self):
        """Return the certificate common_name."""
        return self.cert_data.get("common_name")

    @property
    def subject(self):
        """Return the certificate subject."""
        return self.cert_data.get("subject") or ""

    @property
    def principal(self):
        """Return the Kerberos principal."""
        return self.cert_data.get("principal") or []

    def _get_subject_values(self, oid):
        values = self._x509_obj.subject.get_attributes_for_oid(oid)
        if values:
            return values[0].value
        return None

    def _get_san_values(self, san_type, san_class=None):
        if not self._subject_alternative_names:
            return []
        san_values = self._subject_alternative_names.value.get_values_for_type(
            san_type,
        )
        if san_values and san_class:
            values = []
            for obj in san_values:
                if obj.type_id.dotted_string == san_class.oid:
                    name = san_class(obj.type_id, obj.value).name
                    if name not in values:
                        values.append(name)
            san_values = values

        return san_values

    def _get_key_usage(self):
        key_usages = set()
        if self._key_usage_ext:
            for attr, key_usage in self.KEY_USAGE_ATTR_MAP.items():
                try:
                    key_usage_enabled = getattr(self._key_usage_ext.value, attr)
                except ValueError:
                    pass
                else:
                    if key_usage_enabled:
                        key_usages.add(key_usage)
        return key_usages

    @classmethod
    def _get_extended_key_usage_object_identifier(cls, eku):
        oid = cls.EXTENDED_KEY_USAGES_OID_MAP.get(eku)
        if not oid:
            oid = ObjectIdentifier(eku)
        return oid

    def _get_extended_key_usage(self):
        if not self._extended_key_usage_ext:
            return []
        return [eku.dotted_string for eku in self._extended_key_usage_ext.value]

    @property
    def _subject_alternative_names(self):
        return self._get_x509_ext(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    @property
    def _key_usage_ext(self):
        return self._get_x509_ext(x509.oid.ExtensionOID.KEY_USAGE)

    @property
    def _extended_key_usage_ext(self):
        return self._get_x509_ext(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)

    def _get_x509_ext(self, ext_oid):
        try:
            ext = self._x509_obj.extensions.get_extension_for_oid(ext_oid)
        except x509.ExtensionNotFound:
            return []
        return ext

    def __eq__(self, other):
        """Compare two instances of CertificateProxy for idempotency purposes."""
        # TODO: compare CA here
        #   Currently each provider is responsible for implementing the CA
        #   comparison.
        if not isinstance(other, CertificateProxy):
            raise TypeError(
                "Cannot compare 'CertificateProxy' with '{0}'".format(
                    type(other),
                )
            )

        self._module.debug(
            "Preparing CertificateProxy objects for comparison: "
            "some keys might be added and/or removed."
        )
        self._module.debug("Original A: {0}".format(pformat(self.cert_data)))
        self._module.debug("Original B: {0}".format(pformat(other.cert_data)))

        # Remove empty sequences and strings, false and None values
        #   before comparison happens
        self_info = {k: v for k, v in self.cert_data.items() if v}
        other_info = {k: v for k, v in other.cert_data.items() if v}

        self._module.debug("Comparing CertificateProxy objects:")
        self._module.debug("A: {0}".format(pformat(self_info)))
        self._module.debug("B: {0}".format(pformat(other_info)))

        equals = self_info == other_info
        self._module.debug("A == B: {0}".format(equals))
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
        self._request_id = None

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
                    "Relative path '{0}' not allowed for 'name' parameter (use "
                    "either a simple string or an absolute path)."
                ).format(name)
            )

        base_path = self.module.params.get("directory")
        return os.path.join(
            base_path,
            subdir,
            (name + ext),
        )

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
                auto_renew = self.get_existing_certificate_auto_renew_flag()

                self._existing_certificate = self.certificate_proxy_class.load_from_pem(
                    self.module,
                    cert_pem,
                    csr_pem,
                    auto_renew,
                )
        return self._existing_certificate

    @property
    def csr(self):
        """Instance CertificateProxy for the new certificate request."""
        if self._csr is None:
            self._csr = self.certificate_proxy_class.load_from_params(
                self.module,
                self.module.params,
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

    def _get_ansible_managed(self):
        """New ansible managed comment."""
        return self.module.params.get("__header")

    def _get_hook_script_path(self, dirname):
        script_name = "{cert_name}-{request_id}.sh".format(
            cert_name=os.path.basename(self.module.params.get("name")),
            request_id=self.request_id,
        )
        provider_config_directory = self.module.params.get("provider_config_directory")
        return os.path.join(provider_config_directory, dirname, script_name)

    @property
    def pre_run_script_path(self):
        """Path to pre-run script."""
        return self._get_hook_script_path("pre-scripts")

    @property
    def post_run_script_path(self):
        """Path to post-run script."""
        return self._get_hook_script_path("post-scripts")

    def _convert_hook_param_to_script(self, param_name):
        param = self.module.params.get(param_name)
        if not param:
            return None

        script = ["#!/bin/bash", self._get_ansible_managed(), param]
        return "\n".join(script)

    @property
    def cert_needs_update(self):
        """Verify if the existing certificate needs to be updated."""
        return self.existing_certificate != self.csr

    def _exit_success(self):
        self.module.exit_json(
            changed=self.changed,
            msg=self.message,
        )

    def _set_user_and_group_if_different(self):
        owner = self.module.params.get("owner")
        group = self.module.params.get("group")
        mode = self.module.params.get("mode")
        if group and not mode:
            mode = "0640"

        if not any([owner, group, mode]):
            return False

        file_attrs = {
            "path": self.certificate_file_path,
            "owner": owner,
            "group": group,
            "mode": mode,
            "attributes": None,
            "secontext": [],
        }
        cert_diff = {}
        self.changed = self.module.set_fs_attributes_if_different(
            file_attrs,
            self.changed,
            cert_diff,
        )
        self.module.debug("Certificate fs attribute diff: {0}".format(cert_diff))

        file_attrs["path"] = self.certificate_key_path
        key_diff = {}
        self.changed = self.module.set_fs_attributes_if_different(
            file_attrs,
            self.changed,
            key_diff,
        )
        self.module.debug("Certificate Key fs attribute diff: {0}".format(key_diff))

        return cert_diff or key_diff

    def run(self, check_mode=False):
        """Entry point for the providers called from the actual Ansible module."""
        self.module_input_validation()

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

        hooks_updated = self.create_or_update_hook_scripts(check_mode)
        if hooks_updated:
            self.message += " Pre/Post run hooks updated."
            issue_or_update_cert = True

        if issue_or_update_cert and not check_mode:
            self.request_certificate()

        updated_fs_attrs = self._set_user_and_group_if_different()
        if updated_fs_attrs:
            self.message += " File attributes updated."
        self._exit_success()

    def _write_param_to_file_if_diff(self, param_name, filepath, check_mode):
        param = self._convert_hook_param_to_script(param_name)
        file_exists = os.path.exists(filepath)

        # Remove script if param is empty
        if not param:
            if file_exists:
                os.unlink(filepath)
                return True
            return False

        # Calculate file SHA1
        file_sha1 = ""
        if file_exists:
            file_sha1 = self.module.sha1(filepath)

        # Calculate pamam SHA1
        param_sha1 = hashlib.sha1(to_bytes(param)).hexdigest()

        # if file and param are the same just return
        if param_sha1 == file_sha1:
            return False

        # Changes needs to be performed.

        # If check mode return withot modifications
        if check_mode:
            return True

        # Perform the actual changes
        with open(filepath, "w") as script_fp:
            script_fp.write(param)

        self.module.set_mode_if_different(filepath, "770", True)

        return True

    def create_or_update_hook_scripts(self, check_mode):
        """Create or update pre/post run scripts.

        Create the pre/post run scripts if they don't exist.
        If it exists use SHA1 sum to verify if the files need update.
        In case the script exists and is not longer needed it will be
        removed.
        """
        run_before_changed = self._write_param_to_file_if_diff(
            "run_before", self.pre_run_script_path, check_mode
        )
        run_after_changed = self._write_param_to_file_if_diff(
            "run_after", self.post_run_script_path, check_mode
        )
        return run_before_changed or run_after_changed

    def get_existing_certificate_pem_data(self):
        """Read the PEM data for a certificate from it's file.

        If certificate file is not available return False.
        """
        try:
            with open(self.certificate_file_path, "r") as cert_file:
                return cert_file.read().encode("utf-8")
        except FileNotFoundError:
            return False

    @property
    def request_id(self):
        """Return an unique identifier for this certificate request.

        This property caches the result of the method `_get_request_id`.
        """
        if not self._request_id:
            self._request_id = hashlib.sha1(
                to_bytes(self.certificate_file_path)
            ).hexdigest()[:7]
        return self._request_id

    @abstractmethod
    def get_existing_csr_pem_data(self):
        """Read the PEM data for a CSR.

        Must be implemented by the provider.
        """
        raise NotImplementedError

    @abstractmethod
    def get_existing_certificate_auto_renew_flag(self):
        """Check if the existing certificate is configured for auto renew."""
        raise NotImplementedError

    @abstractmethod
    def module_input_validation(self):
        """Validate module input params.

        Validates the input parameters and it's combinations.
        Needs to be implemented by each provider.
        """
        raise NotImplementedError

    @abstractmethod
    def request_certificate(self):
        """Issues a new certificate or updates an existing certificate.

        Must be implemented by the provider.
        """
        raise NotImplementedError
