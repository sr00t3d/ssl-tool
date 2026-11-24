[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# ssl-tool

![ssl-tool cover](ssl-tool-cover.webp)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/ssl-tool/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requisitos)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20OpenSSL-lightgrey.svg)](#requisitos)

**CLI de Auditoria, Verificação Criptográfica e Gestão SSL/TLS para cPanel & Linux (`ssl-tool.sh`).**

O `ssl-tool.sh` audita certificados X.509 (`Subject`, `Issuer`, `SANs`, validade e dias restantes), valida criptograficamente a correspondência entre chave privada (RSA/ECDSA/Ed25519) e certificado (`KEY_PAIR MATCH`), instala SSLs SNI via `whmapi1 installssl`, realiza backups `chmod 600` antes de remover vhosts SSL e gerencia IPs livres e certificados de serviço.

> **Inspiração Histórica:** Reimplementação limpa em Bash + Python 3.6+ (`v2.0.0`) inspirada no clássico `ssl-tool` (2013, Rishwanth Y, HostGator.com, LLC).

---

## Execução Direta

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/ssl-tool/main/ssl-tool.sh -o ssl-tool.sh
chmod +x ssl-tool.sh
./ssl-tool.sh verify --crt /etc/ssl/certs/example.com.crt --key /etc/ssl/private/example.com.key
```

---

## Exemplo de Saída Real

```text
==================================================================================================
 ssl-tool.sh v2.0.0 | Certificate Verify | 2026-11-24T03:51:10Z
==================================================================================================
STATUS       DAYS  EXPIRES_UTC  KEY_PAIR  SANS / SUBJECT                FILE
-----------  ----  -----------  --------  ----------------------------  ------------------------------
SELF_SIGNED  364   2027-11-24   MATCH     example.com, www.example.com  /tmp/ssl-tool-e2e/example.crt
```

---

## Licença

Distribuído sob a licença [Apache License 2.0](LICENSE).
