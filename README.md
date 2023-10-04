# Certificate System Role

[![woke.yml](https://github.com/linux-system-roles/certificate/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/woke.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/certificate/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/python-unit-test.yml) [![markdownlint.yml](https://github.com/linux-system-roles/certificate/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/markdownlint.yml) [![codeql.yml](https://github.com/linux-system-roles/certificate/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/codeql.yml) [![ansible-test.yml](https://github.com/linux-system-roles/certificate/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/ansible-test.yml) [![ansible-lint.yml](https://github.com/linux-system-roles/certificate/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/certificate/actions/workflows/ansible-lint.yml)

Role for managing TLS/SSL certificate issuance and renewal

Linux system role to issue and renew SSL certificates.

Basic usage:

```yaml
---
- hosts: webserver

  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign

  roles:
    - linux-system-roles.certificate
```

On a RPM-based system this will place the certificate in `/etc/pki/tls/certs/mycert.crt`
and the key in `/etc/pki/tls/private/mycert.key`.

## Requirements

None

## Variables

| Parameter               | Description                                                                                                    | Type | Required | Default           |
|-------------------------|----------------------------------------------------------------------------------------------------------------|:----:|:--------:|-------------------|
| certificate_wait        | If the task should wait for the certificate to be issued.                                                      | bool | no       | yes               |
| certificate\_requests   | A list of dicts representing each certificate to be issued. See [certificate_requests](#certificate_requests). | list | no       | -                 |

### certificate_requests

**Note:** Fields such as `common_name`, `country`, `state`, `locality`,
`organization`, `organizational_unit`, `email`, `key_usage`, and
`extended_key_usage` that can be included in the certificate request
are defined by the RFC 5280.

**Note:** Be aware that the CA might not honor all the requested fields.
For example, even if a request include `country: US`, the CA might issue
the certificate without `country` in it's subject.

**Note:** The fields `dns`, `email` and `ip` are used to define the Subject
Alternative Names (SAN).

| Parameter            | Description                                                                                       | Type        | Required | Default                 |
|----------------------|---------------------------------------------------------------------------------------------------|:-----------:|:--------:|-------------------------|
| name                 | Name of the certificate. A full path can be used to choose the directory where files will be stored.| str       | yes      | -                       |
| ca                   | CA that will issue the certificate. See [CAs and Providers](#cas-and-providers).                  | str         | yes      | -                       |
| dns                  | Domain (or list of domains) to be included in the certificate. Also can provide the default value for [common\_name](#common_name). | str or list | no | - |
| email                | Email (or list of emails) to be included in the certificate.                                      | str or list | no       | -                       |
| ip                   | IP, or list of IPs, to be included in the certificate. IPs can be IPv4, IPv6 or both. Also can provide the default value for [common\_name](#common_name). | str or list | no | - |
| auto_renew           | Indicates if the certificate should be renewed automatically before it expires.                   | bool        | no       | yes                     |
| owner                | User name (or user id) for the certificate and key files.                                         | str         | no       | *User running Ansible*  |
| group                | Group name (or group id) for the certificate and key files.                                       | str         | no       | *Group running Ansible* |
| mode                     | The file system permissions for the certificate and key files.
  | raw         | no       | -                       |
| key\_size            | Generate keys with a specific keysize in bits.                                                    | int         | no       | 2048 - See [key\_size](#key_size) |
| common\_name         | Common Name requested for the certificate subject.                                                | str         | no       | See [common\_name](#common_name)  |
| country              | Country code requested for the certificate subject.                                               | str         | no       | -                       |
| state                | State requested for the certificate subject.                                                      | str         | no       | -                       |
| locality             | Locality requested for the certificate subject (usually city).                                    | str         | no       | -                       |
| organization         | Organization requested for the certificate subject.                                               | str         | no       | -                       |
| organizational_unit  | Organizational unit requested for the certificate subject.                                        | str         | no       | -                       |
| contact\_email       | Contact email requested for the certificate subject.                                              | str         | no       | -                       |
| key\_usage           | Allowed Key Usage for the certificate. For valid values see: [key\_usage](#key_usage).            | list        | no       | See [key\_usage](#key_usage) |
| extended\_key\_usage | Extended Key Usage attributes to be present in the certificate request.                           | list        | no       | See [extended\_key\_usage](#extended_key_usage) |
| run\_before          | Command that should run before saving the certificate. See [run hooks](#run-hooks).               | str         | no       | -                       |
| run\_after           | Command that should run after saving the certificate. See [run hooks](#run-hooks).                | str         | no       | -                       |
| principal            | Kerberos principal.                                                                               | str         | no       | -                       |
| provider             | The underlying method used to request and manage the certificate.                                 | str         | no       | *Varies by CA*          |

### common_name

If `common_name` is not set the role will attempt to use the first
value of `dns` or `ip`, respectively, as the default. If `dns` and
`ip` are also not set, `common_name` will not be included in the certificate.

### key_size

Recommended minimal-values for a certificate key size, from different
organizations, vary across time. In the attempt to provide safe settings,
the default minimal-value for `key_size` will be increased over time.

If you want your certificates to always keep the same `key_size` when
renewed, set this variable to the desired value.

### key_usage

Valid values for `key_usage` are:

* digitalSignature
* nonRepudiation
* keyEncipherment
* dataEncipherment
* keyAgreement
* keyCertSign
* cRLSign
* encipherOnly
* decipherOnly

The defaults for `key_usage` are:

* digitalSignature
* keyEncipherment

### extended_key_usage

Any valid oid can be used to set one or more `extended_key_usage`.
In addition to that there is also a list of known aliases that
will be recognized by the role:

* id-kp-serverAuth
* id-kp-clientAuth
* id-kp-codeSigning
* id-kp-emailProtection
* id-kp-timeStamping
* id-kp-OCSPSigning
* id-kp-ipsecEndSystem
* id-kp-ipsecTunnel
* id-kp-ipsecUser

If `extended_key_usage` is not set the role will default to:

* id-kp-serverAuth
* id-kp-clientAuth

### run hooks

Sometimes you need to execute a command just before a certificate is
renewed and another command just after. In order to do that use
`run_before` and `run_after`.

The value provided to `run_before` and `run_after` will be wrapped and
stored in shell script files that later will be executed by the provider.

## CAs and Providers

| CA               | Providers   | CA description                                  | Requirements                                    |
|------------------|-------------|-------------------------------------------------|-------------------------------------------------|
| self-sign        | certmonger* | Issue self-signed certificates from a local CA. |                                                 |
| ipa              | certmonger* | Issue certificates using the FreeIPA CA.        | Host needs to be enrolled in a FreeIPA server.  |

 *\* Default provider.*

CA represents the CA certificates that will be used to issue and sign the
requested certificate. Provider represents the method used to send the certificate
request to the CA and then retrieve the signed certificate.

If a user chooses `self-sign` CA, with `certmonger` as provider and, later on
decide to change the provider to `openssl`, the CA certificates used in both
cases needs to be the same. *Please note that `openssl` is **not yet a supported**
provider and it's only mentioned here as an example.*

### Certmonger and SELinux

If SELinux is enforced, the `certmonger` service is only able to write or edit
files in directories where the `cert_t` context is present.

Additionally to that, if the scripts executed by `run_before` and `run_after`
parameters need to write or edit files, those scripts also require the `cert_t`
context to be present prior to the role execution.

You can use the `selinux` System Role to manage SELinux contexts.

For more information about `certmonger` and SELinux requirements, see
[certmonger_selinux(8) man pages](https://linux.die.net/man/8/certmonger_selinux).

## Examples

### Issuing a self-signed certificate

Issue a certificate for `*.example.com` and place it in the standard
directory for the distribution.

```yaml
---
- hosts: webserver

  vars:
    certificate_requests:
      - name: mycert
        dns: *.example.com
        ca: self-sign

  roles:
    - linux-system-roles.certificate
```

You can find the directories for each distribution in the following locations:

* Debian/Ubuntu:
  * Certificates: `/etc/ssl/localcerts/certs/`
  * Keys: `/etc/ssl/localcerts/private/`

* RHEL/CentOS/Fedora:
  * Certificates: `/etc/pki/tls/certs/`
  * Keys: `/etc/pki/tls/private/`

### Choosing where to place the certificates

Issue a certificate and key and place them in the specified location.
The example below creates a certificate file in
`/another/path/mycert.crt` and a key file in `/another/path/mycert.key`.

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: /another/path/mycert
        dns: *.example.com
        ca: self-sign

  roles:
    - linux-system-roles.certificate
```

### Issuing certificates with multiple DNS, IP and Email

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns:
          - www.example.com
          - sub1.example.com
          - sub2.example.com
          - sub3.example.com
        ip:
          - 192.0.2.12
          - 198.51.100.65
          - 2001:db8::2:1
        email:
          - sysadmin@example.com
          - support@example.com
        ca: self-sign

  roles:
    - linux-system-roles.certificate
```

### Setting common subject options

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        common_name: www.example.com
        ca: self-sign
        country: US
        state: NY
        locality: New York
        organization: Red Hat
        organizational_unit: platform
        email: admin@example.com
  roles:
    - linux-system-roles.certificate
```

### Setting the certificate key size

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        key_size: 4096
  roles:
    - linux-system-roles.certificate
```

### Setting the "Key Usage" and "Extended Key Usage" (EKU)

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        key_usage:
          - digitalSignature
          - nonRepudiation
          - keyEncipherment
        extended_key_usage:
          - id-kp-clientAuth
          - id-kp-serverAuth
  roles:
    - linux-system-roles.certificate
```

### Don't wait for the certificate to be issued

The certificate issuance can take several minutes depending on the CA.
Because of that it's also possible to request the certificate but not
actually wait for it.

This configuration affects all certificates: if `certificate_wait` is
set to `no` the role does not wait for any certificate to be issued.

```yaml
---
- hosts: webserver
  vars:
    certificate_wait: false
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
  roles:
    - linux-system-roles.certificate
```

### Setting a principal

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        principal: HTTP/www.example.com@EXAMPLE.COM

  roles:
    - linux-system-roles.certificate
```

### Choosing to not auto-renew a certificate

By default certificates generated by the role are set for
auto-renewal. To disable that behavior set `auto_renew: no`.

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        auto_renew: no

  roles:
    - linux-system-roles.certificate
```

### Using FreeIPA to issue a certificate

If your host is enrolled in a FreeIPA server, you also have the option
to use it's CA to issue your certificate. To do that, set `ca: ipa`.

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        principal: HTTP/www.example.com@EXAMPLE.COM
        ca: ipa

  roles:
    - linux-system-roles.certificate
```

### Running a command before or after a certificate is issued

Sometimes you need to execute a command just before a certificate is
renewed and another command just after. To do so, use `run_before`
and `run_after`.

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        run_before: systemctl stop webserver.service
        run_after: systemctl start webserver.service

  roles:
    - linux-system-roles.certificate
```

### Setting the certificate owner and group

If you are using a certificate for a service, for example httpd,
you need to set the certificate owner and group that will own the
certificate. In the following example the owner and group are both
set to httpd.

```yaml
---
- hosts: webserver
  vars:
    certificate_requests:
      - name: mycert
        dns: www.example.com
        ca: self-sign
        owner: httpd
        group: httpd

  roles:
    - linux-system-roles.certificate
```

Note that you can also use UID and GID instead of user and group names.

## Compatibility

Currently supports CentOS 7+, RHEL 7+, Fedora. It has been tested with Debian 10.

## License

MIT

## Author Information

Sergio Oliveira Campos (@seocam)
