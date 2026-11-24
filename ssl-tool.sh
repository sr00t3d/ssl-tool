#!/usr/bin/env bash
# ==============================================================================
# ssl-tool.sh — cPanel & Linux SSL/TLS Certificate Auditor & Manager CLI (v2.0.0)
# ==============================================================================
# Clean-room Bash + Python 3.6+ reimplementation inspired by ssl-tool (2013,
# Rishwanth Y, HostGator.com, LLC).
#
# Eliminates dead Perl/CPAN dependencies (cPanel::PublicAPI, XML::Simple,
# Cpanel::DIp), /root/.accesshash, dead HostGator URLs, obsolete dedicated-IP
# requirements (supports modern SNI), shell injection in openssl calls, and
# insecure /home/hgtransfer backup paths.
#
# Adds OpenSSL X.509 parsing (SANs, Issuer, days remaining, RSA/ECDSA/Ed25519
# key-to-cert cryptographic matching), whmapi1 integration (installssl,
# delete_ssl_vhost, listips, reset_service_ssl_certificates), chmod 600 backups,
# --dry-run, --warn-days + --exit-code (2), and table/json/csv outputs.
#
# License: Apache-2.0
# Author:  Percio Castelo (https://perciocastelo.com.br)
# Repo:    https://github.com/sr00t3d/ssl-tool
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="ssl-tool.sh"
readonly SCRIPT_VERSION="2.0.0"

ACTION=""
TARGET=""
CRT_FILE=""
KEY_FILE=""
CA_FILE=""
SEARCH_DIR=""
BACKUP_DIR="/var/backups/ssl-tool"
WARN_DAYS="30"
DRY_RUN=0
EXIT_CODE_MODE=0
OUTPUT_FMT="table"
QUIET=0
NO_COLOR=0

C_RED=""
C_GREEN=""
C_YELLOW=""
C_CYAN=""
C_BOLD=""
C_RESET=""

init_colors() {
  if [[ "$NO_COLOR" -eq 0 && -t 1 && "$OUTPUT_FMT" == "table" ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_CYAN=$'\033[0;36m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
  fi
}

usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — cPanel & Linux SSL/TLS Certificate Auditor & Manager CLI

Usage:
  ${SCRIPT_NAME} audit <domain> [options]                  Audit certificates for <domain> (read-only)
  ${SCRIPT_NAME} verify --crt <crt> [--key <key>] [opts]   Inspect cert & verify RSA/ECDSA/Ed25519 key match
  ${SCRIPT_NAME} install <domain> --crt <c> --key <k>      Validate & install SSL via whmapi1 (SNI-ready)
  ${SCRIPT_NAME} uninstall <domain> [options]              Backup (0600) & remove SSL vhost via whmapi1
  ${SCRIPT_NAME} list-free-ips [options]                   List unassigned server IPs via whmapi1
  ${SCRIPT_NAME} reset-service <cpanel|mail|ftp|exim|all>  Reset service SSL certificates via whmapi1

Options:
  --crt <path>              Path to X.509 certificate (.crt/.pem)
  --key <path>              Path to private key (.key) for cryptographic pubkey match
  --ca <path>               Optional CA bundle path
  --dir <path>              Extra directory to scan for domain certificates
  --backup-dir <dir>        Backup directory (default: /var/backups/ssl-tool)
  --warn-days <N>           Expiry warning threshold in days (default: 30)
  --dry-run                 Preview install/uninstall/reset actions without applying
  --exit-code               Exit 2 if expired, expiring <= --warn-days, or key mismatch
  -o, --output <fmt>        Output format: table (default), json, csv
  -q, --quiet               Minimal output
  --no-color                Disable ANSI colors
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  ${SCRIPT_NAME} verify --crt /etc/ssl/certs/example.com.crt --key /etc/ssl/private/example.com.key
  ${SCRIPT_NAME} audit example.com --dir /etc/ssl/certs --warn-days 30 --exit-code
  ${SCRIPT_NAME} install example.com --crt cert.crt --key priv.key --ca ca.crt --dry-run
  ${SCRIPT_NAME} list-free-ips -o json
EOF
}

parse_args() {
  local positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -v|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      --crt)
        [[ $# -ge 2 ]] || { printf '[ERR] --crt requires a file path.\n' >&2; exit 1; }
        CRT_FILE="$2"; shift 2 ;;
      --key)
        [[ $# -ge 2 ]] || { printf '[ERR] --key requires a file path.\n' >&2; exit 1; }
        KEY_FILE="$2"; shift 2 ;;
      --ca)
        [[ $# -ge 2 ]] || { printf '[ERR] --ca requires a file path.\n' >&2; exit 1; }
        CA_FILE="$2"; shift 2 ;;
      --dir)
        [[ $# -ge 2 ]] || { printf '[ERR] --dir requires a directory.\n' >&2; exit 1; }
        SEARCH_DIR="$2"; shift 2 ;;
      --backup-dir)
        [[ $# -ge 2 ]] || { printf '[ERR] --backup-dir requires a directory.\n' >&2; exit 1; }
        BACKUP_DIR="$2"; shift 2 ;;
      --warn-days)
        [[ $# -ge 2 ]] || { printf '[ERR] --warn-days requires an integer.\n' >&2; exit 1; }
        WARN_DAYS="$2"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --exit-code) EXIT_CODE_MODE=1; shift ;;
      -o|--output)
        [[ $# -ge 2 ]] || { printf '[ERR] --output requires table|json|csv.\n' >&2; exit 1; }
        OUTPUT_FMT="$2"; shift 2 ;;
      -q|--quiet) QUIET=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      --) shift; while [[ $# -gt 0 ]]; do positional+=("$1"); shift; done ;;
      -*)
        printf '[ERR] Unknown option: %s\n' "$1" >&2
        exit 1 ;;
      *)
        positional+=("$1"); shift ;;
    esac
  done

  if [[ ${#positional[@]} -eq 0 ]]; then
    usage
    exit 0
  fi

  case "${positional[0]}" in
    audit|find|display)
      ACTION="audit"
      TARGET="${positional[1]:-}"
      ;;
    verify|check)
      ACTION="verify"
      TARGET="${positional[1]:-}"
      ;;
    install)
      ACTION="install"
      TARGET="${positional[1]:-}"
      ;;
    uninstall|remove)
      ACTION="uninstall"
      TARGET="${positional[1]:-}"
      ;;
    list-free-ips|freeips)
      ACTION="list-free-ips"
      ;;
    reset-service|resetsrv)
      ACTION="reset-service"
      TARGET="${positional[1]:-}"
      ;;
    *)
      ACTION="audit"
      TARGET="${positional[0]}"
      ;;
  esac

  [[ "$WARN_DAYS" =~ ^[0-9]+$ ]] || { printf '[ERR] --warn-days must be a non-negative integer.\n' >&2; exit 1; }
  case "$OUTPUT_FMT" in
    table|json|csv) ;;
    *) printf '[ERR] Invalid --output: %s (expected table|json|csv)\n' "$OUTPUT_FMT" >&2; exit 1 ;;
  esac
}

main() {
  parse_args "$@"

  if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    printf '[ERR] python3 and openssl are required.\n' >&2
    exit 1
  fi

  init_colors

  local ts_utc
  ts_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  local py_script
  py_script="$(cat <<'PYEOF'
import csv
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

(
    action, target, crt_file, key_file, ca_file, search_dir, backup_dir,
    warn_days_s, dry_run_s, exit_code_s, fmt, quiet_s,
    script_name, script_version, ts_utc,
    c_red, c_green, c_yellow, c_cyan, c_bold, c_reset
) = sys.argv[1:22]

warn_days = int(warn_days_s)
dry_run = dry_run_s == "1"
exit_code_mode = exit_code_s == "1"
quiet = quiet_s == "1"


def run_cmd(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)


def pubkey_sha256_from_cert(path):
    rc, out, _ = run_cmd(["openssl", "x509", "-in", path, "-pubkey", "-noout"])
    if rc != 0 or not out.strip():
        return None
    return hashlib.sha256(out.strip().encode("utf-8")).hexdigest()[:16]


def pubkey_sha256_from_key(path):
    rc, out, _ = run_cmd(["openssl", "pkey", "-in", path, "-pubout"])
    if rc != 0 or not out.strip():
        return None
    return hashlib.sha256(out.strip().encode("utf-8")).hexdigest()[:16]


def parse_cert(path):
    rc, out, err = run_cmd([
        "openssl", "x509", "-in", path, "-noout",
        "-subject", "-issuer", "-dates", "-serial", "-ext", "subjectAltName"
    ])
    if rc != 0:
        # Fallback for older OpenSSL without -ext
        rc, out, err = run_cmd(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-dates", "-serial"])
        if rc != 0:
            return None, (err.strip() or "Failed to parse X.509 certificate")

    subject = "-"
    issuer = "-"
    nb_s = ""
    na_s = ""
    serial = "-"
    sans = []

    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("subject="):
            subject = s[8:].strip()
        elif s.startswith("issuer="):
            issuer = s[7:].strip()
        elif s.startswith("notBefore="):
            nb_s = s[10:].strip()
        elif s.startswith("notAfter="):
            na_s = s[9:].strip()
        elif s.startswith("serial="):
            serial = s[7:].strip()
        elif "DNS:" in s:
            sans.extend(re.findall(r'DNS:([^,\s]+)', s))

    def parse_ossl_date(ds):
        ds_clean = re.sub(r'\s+', ' ', ds.replace("GMT", "").replace("UTC", "")).strip()
        for fmt_s in ("%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(ds_clean, fmt_s).replace(tzinfo=datetime.timezone.utc)
            except Exception:
                pass
        return None

    nb_dt = parse_ossl_date(nb_s)
    na_dt = parse_ossl_date(na_s)
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    days_left = int((na_dt - now_dt).total_seconds() // 86400) if na_dt else None
    self_signed = (subject == issuer and subject != "-")

    if days_left is not None and days_left < 0:
        status = "EXPIRED"
    elif self_signed:
        status = "SELF_SIGNED"
    elif days_left is not None and days_left <= warn_days:
        status = "EXPIRING"
    else:
        status = "VALID"

    return {
        "file": path,
        "status": status,
        "subject": subject,
        "issuer": issuer,
        "self_signed": self_signed,
        "not_before_utc": nb_dt.strftime("%Y-%m-%d") if nb_dt else nb_s,
        "not_after_utc": na_dt.strftime("%Y-%m-%d") if na_dt else na_s,
        "days_left": days_left,
        "serial": serial,
        "sans": sorted(set(sans)),
        "pubkey_fp": pubkey_sha256_from_cert(path),
    }, None


def domain_matches_cert(domain, cert_info):
    dom = domain.lower().strip()
    candidates = list(cert_info["sans"])
    m_cn = re.search(r'CN\s*=\s*([^,/]+)', cert_info["subject"])
    if m_cn:
        candidates.append(m_cn.group(1).strip())
    for c in candidates:
        c = c.lower().strip()
        if c == dom:
            return True
        if c.startswith("*.") and dom.endswith(c[1:]) and dom.count(".") == c.count("."):
            return True
    return False


def emit_output(payload, columns, rows, title):
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(columns)
        for r in rows:
            w.writerow(r)
        sys.stdout.write(buf.getvalue())
        return
    if not quiet:
        print("=" * 98)
        print(f" {c_bold}{script_name} v{script_version}{c_reset} | {title} | {ts_utc}")
        print("=" * 98)
    if not rows:
        print(f"{c_yellow}[NONE]{c_reset} No matching certificates or records found.")
        return
    widths = [len(c) for c in columns]
    for r in rows:
        for i, v in enumerate(r):
            plain = re.sub(r'\033\[[0-9;]*m', '', str(v))
            if len(plain) > widths[i]:
                widths[i] = min(len(plain), 60)
    print(f"{c_bold}" + "  ".join(columns[i].ljust(widths[i]) for i in range(len(columns))) + f"{c_reset}")
    print("  ".join("-" * widths[i] for i in range(len(columns))))
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            s = str(v)
            plain = re.sub(r'\033\[[0-9;]*m', '', s)
            cells.append(s + (" " * max(0, widths[i] - len(plain))))
        print("  ".join(cells))


# ==============================================================================
# VERIFY
# ==============================================================================
if action == "verify":
    if not crt_file or not os.path.isfile(crt_file):
        print("[ERR] Provide --crt <cert_path> to verify.", file=sys.stderr)
        sys.exit(1)
    info, err = parse_cert(crt_file)
    if err:
        print(f"[ERR] {err}", file=sys.stderr)
        sys.exit(1)
    key_match = None
    key_fp = None
    if key_file:
        if not os.path.isfile(key_file):
            print(f"[ERR] Private key not found: {key_file}", file=sys.stderr)
            sys.exit(1)
        key_fp = pubkey_sha256_from_key(key_file)
        key_match = bool(key_fp and info["pubkey_fp"] and key_fp == info["pubkey_fp"])

    dom_match = domain_matches_cert(target, info) if target else None
    issue = info["status"] in ("EXPIRED", "EXPIRING") or (key_match is False) or (dom_match is False)
    info["key_match"] = key_match
    info["domain_match"] = dom_match
    payload = {"tool": script_name, "version": script_version, "action": "verify", "timestamp_utc": ts_utc, "certificate": info}

    st_disp = info["status"]
    if fmt == "table":
        st_disp = f"{c_green}{st_disp}{c_reset}" if st_disp == "VALID" else (f"{c_red}{st_disp}{c_reset}" if st_disp == "EXPIRED" else f"{c_yellow}{st_disp}{c_reset}")
    km_s = "MATCH" if key_match is True else ("MISMATCH" if key_match is False else "-")
    rows = [[st_disp, str(info["days_left"]) if info["days_left"] is not None else "-", info["not_after_utc"], km_s, ", ".join(info["sans"][:3]) or info["subject"][:36], crt_file]]
    emit_output(payload, ["STATUS", "DAYS", "EXPIRES_UTC", "KEY_PAIR", "SANS / SUBJECT", "FILE"], rows, "Certificate Verify")
    if exit_code_mode and issue:
        sys.exit(2)
    sys.exit(0)

# ==============================================================================
# AUDIT
# ==============================================================================
elif action == "audit":
    if not target:
        print("[ERR] Usage: ssl-tool.sh audit <domain> [--dir /etc/ssl/certs]", file=sys.stderr)
        sys.exit(1)
    dom = target.lower().strip()
    dirs = [search_dir] if search_dir else ["/var/cpanel/ssl/apache_tls", "/etc/ssl/certs", "/usr/share/ssl/certs"]
    cand_files = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for cur, _, files in os.walk(d):
            for fn in files:
                if fn.endswith((".crt", ".pem", "combined")):
                    if search_dir or dom in fn.lower() or dom in cur.lower():
                        cand_files.append(os.path.join(cur, fn))

    certs = []
    issue = False
    for fp in sorted(set(cand_files)):
        info, err = parse_cert(fp)
        if info and (domain_matches_cert(dom, info) or dom in fp.lower()):
            if info["status"] in ("EXPIRED", "EXPIRING"):
                issue = True
            certs.append(info)

    payload = {"tool": script_name, "version": script_version, "action": "audit", "timestamp_utc": ts_utc, "domain": dom, "count": len(certs), "certificates": certs}
    rows = []
    for c in certs:
        st_disp = c["status"]
        if fmt == "table":
            st_disp = f"{c_green}{st_disp}{c_reset}" if st_disp == "VALID" else (f"{c_red}{st_disp}{c_reset}" if st_disp == "EXPIRED" else f"{c_yellow}{st_disp}{c_reset}")
        rows.append([st_disp, str(c["days_left"]) if c["days_left"] is not None else "-", c["not_after_utc"], ", ".join(c["sans"][:3]) or "-", c["file"]])
    emit_output(payload, ["STATUS", "DAYS", "EXPIRES_UTC", "SANS", "FILE"], rows, f"SSL Audit | {dom}")
    if exit_code_mode and (issue or not certs):
        sys.exit(2)
    sys.exit(0)

# ==============================================================================
# INSTALL
# ==============================================================================
elif action == "install":
    if not target or not crt_file or not key_file:
        print("[ERR] Usage: ssl-tool.sh install <domain> --crt <cert> --key <key> [--ca <ca>]", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(crt_file) or not os.path.isfile(key_file):
        print("[ERR] --crt or --key file does not exist.", file=sys.stderr)
        sys.exit(1)
    info, err = parse_cert(crt_file)
    if err:
        print(f"[ERR] Invalid certificate: {err}", file=sys.stderr)
        sys.exit(1)
    if not domain_matches_cert(target, info):
        print(f"[ERR] Certificate SANs/CN do not cover domain '{target}'.", file=sys.stderr)
        sys.exit(1)
    kfp = pubkey_sha256_from_key(key_file)
    if not kfp or kfp != info["pubkey_fp"]:
        print("[ERR] Private key does NOT match certificate public key!", file=sys.stderr)
        sys.exit(1)

    whm = shutil.which("whmapi1")
    if dry_run:
        payload = {"tool": script_name, "version": script_version, "action": "install", "dry_run": True, "domain": target, "pubkey_fp": kfp, "not_after_utc": info["not_after_utc"]}
        emit_output(payload, ["DOMAIN", "PUBKEY_FP", "EXPIRES_UTC", "STATUS"], [[target, kfp, info["not_after_utc"], "DRY-RUN (VERIFIED)"]], f"Install SSL [DRY-RUN] | {target}")
        sys.exit(0)

    if not whm:
        print("[ERR] whmapi1 not found (must run on cPanel/WHM server).", file=sys.stderr)
        sys.exit(1)
    crt_raw = urllib.parse.quote(open(crt_file, "r", encoding="utf-8").read())
    key_raw = urllib.parse.quote(open(key_file, "r", encoding="utf-8").read())
    cmd = [whm, "--output=json", "installssl", f"domain={target}", f"crt={crt_raw}", f"key={key_raw}"]
    if ca_file and os.path.isfile(ca_file):
        cmd.append(f"cab={urllib.parse.quote(open(ca_file, 'r', encoding='utf-8').read())}")
    rc, out, err = run_cmd(cmd, timeout=60)
    if rc != 0:
        print(f"[ERR] whmapi1 installssl failed: {err or out}", file=sys.stderr)
        sys.exit(1)
    emit_output({"tool": script_name, "action": "install", "domain": target, "status": "INSTALLED"}, ["DOMAIN", "PUBKEY_FP", "STATUS"], [[target, kfp, "INSTALLED"]], f"Install SSL | {target}")
    sys.exit(0)

# ==============================================================================
# UNINSTALL
# ==============================================================================
elif action == "uninstall":
    if not target:
        print("[ERR] Usage: ssl-tool.sh uninstall <domain>", file=sys.stderr)
        sys.exit(1)
    whm = shutil.which("whmapi1")
    if dry_run:
        emit_output({"tool": script_name, "action": "uninstall", "dry_run": True, "domain": target}, ["DOMAIN", "STATUS"], [[target, "DRY-RUN"]], f"Uninstall SSL [DRY-RUN] | {target}")
        sys.exit(0)
    if not whm:
        print("[ERR] whmapi1 not found.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    rc_f, out_f, _ = run_cmd([whm, "--output=json", "fetchsslinfo", f"domain={target}"], timeout=30)
    bak_path = os.path.join(backup_dir, f"{target}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json")
    if rc_f == 0 and out_f:
        fd = os.open(bak_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as bf:
            bf.write(out_f + "\n")
    rc, out, err = run_cmd([whm, "--output=json", "delete_ssl_vhost", f"host={target}"], timeout=45)
    if rc != 0:
        print(f"[ERR] delete_ssl_vhost failed: {err or out}", file=sys.stderr)
        sys.exit(1)
    emit_output({"tool": script_name, "action": "uninstall", "domain": target, "backup": bak_path}, ["DOMAIN", "BACKUP", "STATUS"], [[target, bak_path, "REMOVED"]], f"Uninstall SSL | {target}")
    sys.exit(0)

# ==============================================================================
# LIST-FREE-IPS
# ==============================================================================
elif action == "list-free-ips":
    whm = shutil.which("whmapi1")
    if not whm:
        print("[ERR] whmapi1 not found.", file=sys.stderr)
        sys.exit(1)
    rc, out, err = run_cmd([whm, "--output=json", "listips"], timeout=30)
    if rc != 0:
        print(f"[ERR] whmapi1 listips failed: {err or out}", file=sys.stderr)
        sys.exit(1)
    data = json.loads(out)
    free_ips = [x for x in data.get("data", {}).get("ip", []) if str(x.get("used", "1")) == "0"]
    rows = [[x.get("ip", "-"), x.get("netmask", "-"), x.get("if", "-")] for x in free_ips]
    emit_output({"tool": script_name, "action": "list-free-ips", "count": len(free_ips), "ips": free_ips}, ["IP", "NETMASK", "INTERFACE"], rows, "Free Server IPs")
    sys.exit(0)

# ==============================================================================
# RESET-SERVICE
# ==============================================================================
elif action == "reset-service":
    valid_srvs = ("cpanel", "mail", "ftp", "exim", "all")
    if target not in valid_srvs:
        print(f"[ERR] Specify service: {', '.join(valid_srvs)}", file=sys.stderr)
        sys.exit(1)
    srvs = ["cpanel", "dovecot", "ftp", "exim"] if target == "all" else (["dovecot"] if target == "mail" else [target])
    if dry_run:
        emit_output({"tool": script_name, "action": "reset-service", "dry_run": True, "services": srvs}, ["SERVICE", "STATUS"], [[s, "DRY-RUN"] for s in srvs], "Reset Service SSL [DRY-RUN]")
        sys.exit(0)
    whm = shutil.which("whmapi1")
    if not whm:
        print("[ERR] whmapi1 not found.", file=sys.stderr)
        sys.exit(1)
    res = []
    for s in srvs:
        rc, out, err = run_cmd([whm, "--output=json", "reset_service_ssl_certificates", f"service={s}"], timeout=45)
        res.append({"service": s, "status": "RESET" if rc == 0 else f"FAILED: {err or out}"})
    emit_output({"tool": script_name, "action": "reset-service", "results": res}, ["SERVICE", "STATUS"], [[r["service"], r["status"]] for r in res], "Reset Service SSL")
    sys.exit(0)
PYEOF
)"

  python3 -c "$py_script" \
    "$ACTION" "$TARGET" "$CRT_FILE" "$KEY_FILE" "$CA_FILE" "$SEARCH_DIR" "$BACKUP_DIR" \
    "$WARN_DAYS" "$DRY_RUN" "$EXIT_CODE_MODE" "$OUTPUT_FMT" "$QUIET" \
    "$SCRIPT_NAME" "$SCRIPT_VERSION" "$ts_utc" \
    "$C_RED" "$C_GREEN" "$C_YELLOW" "$C_CYAN" "$C_BOLD" "$C_RESET"
}

main "$@"
