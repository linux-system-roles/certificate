"""Parse certificate data into JSON format."""

from ansible.module_utils.basic import AnsibleModule

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import decoder
from pyasn1.type import char, namedtype, tag, univ
import struct


def load_unknown_certificate_from_data(cert_data):
    """Load certificate from data."""
    try:
        return x509.load_pem_x509_certificate(cert_data, backend=default_backend())
    except ValueError:
        return x509.load_der_x509_certificate(cert_data, backend=default_backend())


def load_certificate_from_file(filename):
    """Load cerficate from file."""
    with open(filename, "rb") as cert_file:
        return load_unknown_certificate_from_data(cert_file.read())


def parse_cert_timestamp(cert_datetime):
    """Ensure time is in GeneralizedTime format (YYYYMMDDHHMMSSZ)."""
    return cert_datetime.strftime("%Y%m%d%H%M%SZ") if cert_datetime else None


def to_hex_str(value):
    """Convert byte list to "XX:XX:XX..." string."""
    # pylint: disable=C0209
    fmtstr = str(len(value)) + "B"
    intlist = struct.unpack(fmtstr, value)
    return ":".join("{0:02X}".format(byte) for byte in intlist)


def decode_kerberos_principalname(data):
    """Decode Kerberos principalname."""

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

    principal = decoder.decode(data, asn1Spec=_KRB5PrincipalName())[0]
    realm = str(principal["realm"]).replace("\\", "\\\\").replace("@", "\\@")
    name = principal["principalName"]["name-string"]
    name = "/".join(
        str(n).replace("\\", "\\\\").replace("/", "\\/").replace("@", "\\@")
        for n in name
    )
    name = "{0}@{1}".format(name, realm)  # pylint: disable=C0209
    return name


def parse_san(ext):
    """Parse subjectAltName from a certificate extension."""
    san_class_name_map = {
        x509.DNSName: "DNS",
        x509.IPAddress: "IP Address",
        x509.RFC822Name: "email",
    }
    oid_class_map = {
        "1.3.6.1.5.2.2": lambda name, value: (
            "Kerberos principalname",
            decode_kerberos_principalname(value),
        ),
        "1.3.6.1.4.1.311.20.2.3": lambda name, value: (
            "Universal Principal Name (UPN)",
            decoder.decode(value, asn1Spec=char.UTF8String())[0],
        ),
    }
    result = []

    for san in ext.value:
        name = san_class_name_map.get(san.__class__, "Unknown")
        value = san.value
        oid = getattr(san, "type_id", None)
        if oid:
            oid = oid.dotted_string

        name, value = oid_class_map.get(
            oid,
            lambda name, value: (name, value),
        )(name, value)

        san_attrs = {"name": name, "value": str(value)}
        if oid:
            san_attrs["oid"] = oid
        result.append(san_attrs)

    return result


def parse_certificate_extensions(cert):
    """Parse certificate extensions."""
    oid_name = {
        "1.3.6.1.5.5.7.3.1": "id-kp-serverAuth",
        "1.3.6.1.5.5.7.3.2": "id-kp-clientAuth",
        "1.3.6.1.5.5.7.3.3": "id-kp-codeSigning",
        "1.3.6.1.5.5.7.3.4": "id-kp-emailProtection",
        "1.3.6.1.5.5.7.3.5": "id-kp-ipsecEndSystem",
        "1.3.6.1.5.5.7.3.6": "id-kp-ipsecTunnel",
        "1.3.6.1.5.5.7.3.7": "id-kp-ipsecUser",
        "1.3.6.1.5.5.7.3.8": "id-kp-timeStamping",
        "1.3.6.1.5.5.7.3.9": "id-kp-OCSPSigning",
        "1.3.6.1.5.5.7.3.10": "id-kp-dvcs",
        "1.3.6.1.5.5.7.3.11": "id-kp-sbgpCertAAServerAuth",
        "1.3.6.1.5.5.7.3.12": "id-kp-scvp-responder",
        "1.3.6.1.5.5.7.3.13": "id-kp-eapOverPPP",
        "1.3.6.1.5.5.7.3.14": "id-kp-eapOverLAN",
        "1.3.6.1.5.5.7.3.15": "id-kp-scvpServer",
        "1.3.6.1.5.5.7.3.16": "id-kp-scvpClient",
        "1.3.6.1.5.5.7.3.17": "id-kp-ipsecIKE",
        "1.3.6.1.5.5.7.3.18": "id-kp-capwapAC",
        "1.3.6.1.5.5.7.3.19": "id-kp-capwapWTP",
        "1.3.6.1.5.5.7.3.20": "id-kp-SIPDomain",
        "1.3.6.1.5.5.7.3.21": "id-kp-secureShellClient",
        "1.3.6.1.5.5.7.3.22": "id-kp-secureShellServer",
        "1.3.6.1.5.5.7.3.23": "id-kp-sendRouter",
        "1.3.6.1.5.5.7.3.24": "id-kp-sendProxy",
        "1.3.6.1.5.5.7.3.25": "id-kp-sendOwner",
        "1.3.6.1.5.5.7.3.26": "id-kp-sendProxiedOwner",
        "1.3.6.1.5.5.7.3.27": "id-kp-cmcCA",
        "1.3.6.1.5.5.7.3.28": "id-kp-cmcRA",
        "1.3.6.1.5.5.7.3.29": "id-kp-cmcArchive",
        "2.5.29.37.0": "anyExtendedKeyUsage",
        "1.3.6.1.5.2.2": "id-pkinit-san",  # Kerberos principalname
        "1.3.6.1.4.1.311.20.2.3": "upn",  # Universal Principal Name
    }
    extensions = {}
    for ext in cert.extensions:
        name = ext.oid._name  # pylint: disable=protected-access
        extensions.setdefault(name, {}).update(
            {
                "critical": ext.critical,
                "value": {
                    "extendedKeyUsage": lambda ext: [
                        {
                            "name": oid_name.get(eku.dotted_string),
                            "oid": eku.dotted_string,
                        }
                        for eku in ext.value
                    ],
                    "keyUsage": lambda ext: [
                        ku.lstrip("_")
                        for ku, active in vars(ext.value).items()
                        if active
                    ],
                    "subjectKeyIdentifier": lambda ext: to_hex_str(ext.value.digest),
                    "authorityKeyIdentifier": lambda ext: to_hex_str(
                        ext.value.key_identifier
                    ),
                    "basicConstraints": lambda ext: {
                        constraint.lstrip("_"): value
                        for constraint, value in vars(ext.value).items()
                        if value is not None
                    },
                    "authorityInfoAccess": lambda ext: [
                        {
                            # pylint: disable=protected-access
                            "method": info.access_method._name,
                            "location": info.access_location.value,
                        }
                        for info in ext.value
                    ],
                    "cRLDistributionPoints": lambda ext: [
                        {
                            "full_name": [
                                full_name.value for full_name in dist_point.full_name
                            ],
                            "crl_issuer": [
                                {
                                    # pylint: disable=protected-access
                                    dn_part.oid._name: dn_part.value
                                    for dn_part in issuer.value
                                }
                                for issuer in dist_point.crl_issuer or []
                            ],
                        }
                        for dist_point in ext.value
                    ],
                    "subjectAltName": parse_san,
                }.get(name, lambda ext: "Unsupported extension.")(ext),
            }
        )
    return extensions


def decode_certificate(filename):
    """Decode certificate found in filename."""
    cert = load_certificate_from_file(filename)
    result = {
        "validity": {
            k: parse_cert_timestamp(getattr(cert, k, None))
            for k in ["not_valid_after", "not_valid_before"]
        },
        "signature_algorithm": {
            # pylint: disable=protected-access
            "algorithm": cert.signature_algorithm_oid._name,
            "signature": to_hex_str(cert.signature),
        },
        "key_size": cert.public_key().key_size,
        "subject": [
            {
                "name": attr.oid._name,  # pylint: disable=protected-access
                "oid": attr.oid.dotted_string,
                "value": attr.value,
            }
            for attr in cert.subject
        ],
        "extensions": parse_certificate_extensions(cert),
    }
    return result


def main():
    """Execute module."""
    module = AnsibleModule(
        argument_spec={"filename": {"type": "str", "required": True}},
        supports_check_mode=False,
    )
    module.exit_json(
        changed=False,
        certificate=decode_certificate(module.params.get("filename")),
    )


if __name__ == "__main__":
    main()
