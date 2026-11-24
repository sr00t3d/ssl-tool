[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# ssl-tool

![ssl-tool cover](ssl-tool-cover.webp)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/ssl-tool/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requirements)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20OpenSSL-lightgrey.svg)](#requirements)

**cPanel & Linux SSL/TLS Certificate Auditor, Cryptographic Key Verifier & WHM Manager CLI.**

`ssl-tool.sh` audits installed X.509 certificates (`Subject`, `Issuer`, `SANs`, expiry & days remaining), cryptographically verifies RSA/ECDSA/Ed25519 private key matches (`pubkey_fp`), validates SAN coverage and installs SNI certificates via `whmapi1 installssl`, backs up active SSLs with `chmod 600` before `delete_ssl_vhost`, lists free server IPs (`listips`), and resets service SSLs (`reset_service_ssl_certificates`).

> **Historical Inspiration:** Clean-room Bash + Python 3.6+ `v2.0.0` reimplementation inspired by `ssl-tool` (2013, Rishwanth Y, HostGator.com, LLC). Eliminates dead CPAN/cPanel Perl dependencies (`cPanel::PublicAPI`, `XML::Simple`, `Cpanel::DIp`), `/root/.accesshash`, obsolete dedicated-IP requirements (supports modern SNI), shell injection in `openssl x509 -in`, and insecure `/home/hgtransfer` backup paths.

---

## Requirements

- Linux with Bash 4.0+, Python 3.6+, and `openssl`
- cPanel `whmapi1` (required only for live `install`, `uninstall`, `list-free-ips`, and `reset-service` actions)

---

## Direct Execution

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/ssl-tool/main/ssl-tool.sh -o ssl-tool.sh
chmod +x ssl-tool.sh
./ssl-tool.sh verify --crt /etc/ssl/certs/example.com.crt --key /etc/ssl/private/example.com.key
```

---

## Usage

```bash
# 1. Verify certificate validity + RSA/ECDSA/Ed25519 key match + domain SAN match
./ssl-tool.sh verify example.com --crt cert.crt --key priv.key --exit-code

# 2. Audit all certificates matching a domain on the server (read-only)
./ssl-tool.sh audit example.com --warn-days 30 --exit-code

# 3. Preview or execute a verified SNI SSL install via whmapi1
sudo ./ssl-tool.sh install example.com --crt cert.crt --key priv.key --ca ca.crt --dry-run

# 4. Uninstall SSL cleanly with chmod 600 JSON backup
sudo ./ssl-tool.sh uninstall example.com
```

---

## Real Output Example

```text
==================================================================================================
 ssl-tool.sh v2.0.0 | Certificate Verify | 2026-11-24T03:51:10Z
==================================================================================================
STATUS       DAYS  EXPIRES_UTC  KEY_PAIR  SANS / SUBJECT                FILE
-----------  ----  -----------  --------  ----------------------------  ------------------------------
SELF_SIGNED  364   2027-11-24   MATCH     example.com, www.example.com  /tmp/ssl-tool-e2e/example.crt
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
