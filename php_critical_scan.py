#!/usr/bin/env python3
"""Safe exposure checker for CVE-2026-109618 and CVE-2026-109619.

This tool deliberately does not send exploit payloads.  Local mode inspects an
installed PHP runtime.  URL mode fingerprints normal HTTP responses and only
makes a definitive version assessment when a PHP version is disclosed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


CVES = ["CVE-2026-109618", "CVE-2026-109619"]
ADVISORY_URL = "https://www.php.net/archive/2026.php#2026-10-21-5"
FIXED_RELEASES: Dict[Tuple[int, int], Tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
VERSION_RE = re.compile(
    r"(?<!\d)(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<suffix>(?:[-+._]?[A-Za-z][A-Za-z0-9._-]*)?)",
    re.IGNORECASE,
)
PHP_VERSION_RE = re.compile(
    r"(?i)\bPHP(?:\s+Version|[/\s:])\s*"
    r"(?P<version>\d+\.\d+\.\d+(?:[-+._]?[A-Za-z][A-Za-z0-9._-]*)?)"
)


@dataclass
class Assessment:
    status: str
    version: Optional[str]
    summary: str
    fixed_release: Optional[str] = None
    vendor_backport_possible: bool = False


@dataclass
class ScanResult:
    target: str
    mode: str
    status: str
    summary: str
    version: Optional[str] = None
    fixed_release: Optional[str] = None
    sapi: Optional[str] = None
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    evidence: List[str] = field(default_factory=list)
    mitigations: Dict[str, object] = field(default_factory=dict)
    details: Dict[str, object] = field(default_factory=dict)
    error: Optional[str] = None


def parse_version(value: str) -> Optional[Tuple[int, int, int, str, str]]:
    match = VERSION_RE.search(value or "")
    if not match:
        return None
    normalized = f"{match.group('major')}.{match.group('minor')}.{match.group('patch')}"
    suffix = match.group("suffix") or ""
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        suffix,
        normalized + suffix,
    )


def assess_version(value: str) -> Assessment:
    parsed = parse_version(value)
    if not parsed:
        return Assessment("UNKNOWN", None, "No usable PHP version was found.")

    major, minor, patch, suffix, display = parsed
    branch = (major, minor)

    if major < 8 or (major == 8 and minor < 2):
        return Assessment(
            "LIKELY_AFFECTED",
            display,
            "This upstream PHP branch predates the fixed releases and is end-of-life; a vendor backport must be verified separately.",
            vendor_backport_possible=True,
        )

    if branch in FIXED_RELEASES:
        fixed = FIXED_RELEASES[branch]
        fixed_text = ".".join(str(part) for part in fixed)
        if (major, minor, patch) >= fixed:
            return Assessment(
                "PATCHED",
                display,
                f"PHP {display} is at or above the fixed {fixed_text} release for this branch.",
                fixed_text,
            )
        return Assessment(
            "AFFECTED",
            display,
            f"PHP {display} is older than the fixed {fixed_text} release.",
            fixed_text,
        )

    # The first PHP 8.6 build containing the fixes is 8.6.0 RC4.
    if branch == (8, 6) and patch == 0:
        rc_match = re.search(r"(?i)rc[._-]?(\d+)", suffix)
        if rc_match:
            rc_number = int(rc_match.group(1))
            if rc_number >= 4:
                return Assessment("PATCHED", display, "PHP 8.6.0 RC4 or newer contains the fixes.", "8.6.0RC4")
            return Assessment("AFFECTED", display, "PHP 8.6.0 pre-RC4 builds do not contain the fixes.", "8.6.0RC4")
        if re.search(r"(?i)(?:alpha|beta)", suffix):
            return Assessment("AFFECTED", display, "PHP 8.6.0 alpha/beta builds predate the fixed RC4 build.", "8.6.0RC4")
        if suffix:
            return Assessment("UNKNOWN", display, "Unrecognized PHP 8.6 prerelease; verify that it includes the RC4 fixes.", "8.6.0RC4")
        return Assessment("PATCHED", display, "A stable PHP 8.6.0 release postdates the fixed RC4 build.", "8.6.0RC4")

    if major > 8 or (major == 8 and minor > 6):
        return Assessment("PATCHED", display, "This PHP release postdates the fixed releases.")

    return Assessment("UNKNOWN", display, "This PHP branch is not in the official fixed-release table; verify with the vendor.")


def ini_bool(value: object) -> Optional[bool]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "on", "true", "yes"}:
        return True
    if text in {"0", "off", "false", "no", ""}:
        return False
    return None


def ini_size(value: object) -> Optional[int]:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text == "-1":
        return -1
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]?)b?", text)
    if not match:
        return None
    amount = float(match.group(1))
    scale = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[match.group(2)]
    return int(amount * scale)


def evaluate_mitigations(version: Optional[str], ini: Dict[str, object]) -> Dict[str, object]:
    memory_limit = ini.get("memory_limit")
    post_max_size = ini.get("post_max_size")
    upload_max_filesize = ini.get("upload_max_filesize")
    progress = ini.get("session.upload_progress.enabled")
    backtraces = ini.get("fatal_error_backtraces")
    post_bytes = ini_size(post_max_size)
    upload_bytes = ini_size(upload_max_filesize)

    checks: Dict[str, object] = {
        "notice": "These are partial mitigations only. Updating PHP is the complete fix.",
        "memory_limit_unlimited": {
            "value": memory_limit,
            "present": ini_size(memory_limit) == -1,
            "protects": "Reduces a controllable OOM path for CVE-2026-109618.",
        },
        "post_size_bounded": {
            "value": post_max_size,
            "present": post_bytes is not None and 0 <= post_bytes <= 32 * 1024**2,
            "protects": "Reduces multipart request exposure for CVE-2026-109618.",
        },
        "upload_below_post": {
            "upload_max_filesize": upload_max_filesize,
            "post_max_size": post_max_size,
            "present": (
                upload_bytes is not None
                and post_bytes is not None
                and upload_bytes >= 0
                and post_bytes >= 0
                and upload_bytes < post_bytes
            ),
            "protects": "Matches the official request-size hardening guidance.",
        },
        "session_upload_progress_disabled": {
            "value": progress,
            "present": ini_bool(progress) is False,
            "protects": "Blocks the confirmed session path for CVE-2026-109619.",
        },
    }

    parsed = parse_version(version or "")
    if parsed and parsed[:2] == (8, 5):
        checks["fatal_error_backtraces_disabled"] = {
            "value": backtraces,
            "present": ini_bool(backtraces) is False,
            "protects": "Blocks the confirmed PHP 8.5 fatal-backtrace path for CVE-2026-109619.",
        }
    return checks


LOCAL_PROBE = r'''
$result = array(
  "version" => PHP_VERSION,
  "sapi" => PHP_SAPI,
  "binary" => PHP_BINARY,
  "ini_loaded_file" => php_ini_loaded_file(),
  "ini_scanned_files" => php_ini_scanned_files(),
  "ini" => array(
    "memory_limit" => ini_get("memory_limit"),
    "post_max_size" => ini_get("post_max_size"),
    "upload_max_filesize" => ini_get("upload_max_filesize"),
    "session.upload_progress.enabled" => ini_get("session.upload_progress.enabled"),
    "fatal_error_backtraces" => ini_get("fatal_error_backtraces"),
    "expose_php" => ini_get("expose_php")
  )
);
echo json_encode($result, JSON_UNESCAPED_SLASHES);
'''.strip()


def scan_local(php_binary: str, timeout: float) -> ScanResult:
    resolved = shutil.which(php_binary) if not Path(php_binary).exists() else str(Path(php_binary))
    if not resolved:
        return ScanResult(php_binary, "local", "ERROR", "PHP executable was not found.", error="not found")
    try:
        completed = subprocess.run(
            [resolved, "-r", LOCAL_PROBE],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ScanResult(php_binary, "local", "ERROR", "Could not inspect the PHP runtime.", error=str(exc))
    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout).strip()[:500]
        return ScanResult(php_binary, "local", "ERROR", "PHP returned an error during the read-only probe.", error=error)
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return ScanResult(php_binary, "local", "ERROR", "PHP returned invalid probe output.", error=str(exc))

    assessment = assess_version(str(data.get("version", "")))
    sapi = str(data.get("sapi") or "")
    evidence = [f"PHP binary: {data.get('binary')}", f"SAPI: {sapi}"]
    if sapi.lower() in {"apache2handler", "apache"} or "apache" in sapi.lower():
        evidence.append("Apache mod_php is the highest-risk SAPI identified by the PHP advisory.")
    ini = data.get("ini") if isinstance(data.get("ini"), dict) else {}
    return ScanResult(
        target=resolved,
        mode="local",
        status=assessment.status,
        summary=assessment.summary,
        version=assessment.version,
        fixed_release=assessment.fixed_release,
        sapi=sapi,
        evidence=evidence,
        mitigations=evaluate_mitigations(assessment.version, ini),
        details={
            "ini_loaded_file": data.get("ini_loaded_file"),
            "ini_scanned_files": data.get("ini_scanned_files"),
            "vendor_backport_possible": assessment.vendor_backport_possible,
            "ini": ini,
        },
    )


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("put credentials in --header, not in the URL")
    return urllib.parse.urlunsplit(parsed)


def parse_headers(values: Sequence[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise ValueError(f"invalid header {item!r}; expected NAME: VALUE")
        name, value = item.split(":", 1)
        name = name.strip()
        if not name or any(char in name for char in "\r\n") or any(char in value for char in "\r\n"):
            raise ValueError("invalid HTTP header")
        headers[name] = value.strip()
    return headers


def build_opener(insecure: bool, proxy: Optional[str]) -> urllib.request.OpenerDirector:
    handlers: List[object] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fingerprint_php(headers: Sequence[Tuple[str, str]], body: bytes) -> Tuple[Optional[str], List[str]]:
    version: Optional[str] = None
    evidence: List[str] = []
    for name, value in headers:
        safe_value = value.replace("\r", " ").replace("\n", " ")[:160]
        if name.lower() in {"x-powered-by", "server"}:
            match = PHP_VERSION_RE.search(value)
            if match:
                version = match.group("version")
                evidence.append(f"{name}: {safe_value}")
            elif re.search(r"(?i)\bPHP\b", value):
                evidence.append(f"{name} identifies PHP without a version")
        if name.lower() == "set-cookie" and re.search(r"(?i)(?:^|[;,\s])PHPSESSID=", value):
            evidence.append("A PHPSESSID cookie was observed (value omitted).")

    sample = body[:131072].decode("latin-1", errors="ignore")
    body_match = re.search(r"(?i)PHP\s+Version\s*</?[^>]*>\s*(\d+\.\d+\.\d+(?:[-+._]?[A-Za-z][A-Za-z0-9._-]*)?)", sample)
    if not body_match:
        body_match = PHP_VERSION_RE.search(sample)
    if body_match:
        body_version = body_match.group(1) if body_match.lastindex == 1 else body_match.group("version")
        version = version or body_version
        evidence.append(f"Response body discloses PHP {body_version}.")
    return version, list(dict.fromkeys(evidence))


def scan_url(
    target: str,
    timeout: float,
    insecure: bool,
    proxy: Optional[str],
    extra_headers: Dict[str, str],
) -> ScanResult:
    try:
        url = normalize_url(target)
    except ValueError as exc:
        return ScanResult(target, "url", "ERROR", "Invalid target URL.", error=str(exc))

    headers = {
        "User-Agent": "PHP-Critical-Exposure-Check/1.0 (+safe-version-fingerprint)",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "Connection": "close",
    }
    headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = build_opener(insecure, proxy)
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            body = response.read(131072)
            response_headers = list(response.headers.items())
            final_url = response.geturl()
            status_code = response.getcode()
    except Exception as exc:  # Network libraries expose several platform-specific failures.
        return ScanResult(url, "url", "ERROR", "HTTP fingerprint request failed.", error=str(exc))

    version, evidence = fingerprint_php(response_headers, body)
    if version:
        assessment = assess_version(version)
        return ScanResult(
            target=url,
            mode="url",
            status=assessment.status,
            summary=assessment.summary + " Remote version headers can be hidden, stale, or altered; confirm on the host.",
            version=assessment.version,
            fixed_release=assessment.fixed_release,
            final_url=final_url,
            http_status=status_code,
            evidence=evidence,
            details={"vendor_backport_possible": assessment.vendor_backport_possible},
        )

    if evidence:
        return ScanResult(
            target=url,
            mode="url",
            status="PHP_VERSION_HIDDEN",
            summary="PHP evidence was found, but the version is hidden. Run local mode on the server or verify the package inventory.",
            final_url=final_url,
            http_status=status_code,
            evidence=evidence,
        )
    return ScanResult(
        target=url,
        mode="url",
        status="INCONCLUSIVE",
        summary="No PHP version was exposed in this normal response. This does not prove that PHP is absent or patched.",
        final_url=final_url,
        http_status=status_code,
    )


def report_document(results: Sequence[ScanResult]) -> Dict[str, object]:
    counts: Dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return {
        "scanner": "php-critical-scan-2026-10-21",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cves": CVES,
        "official_advisory": ADVISORY_URL,
        "safe_scan": True,
        "counts": counts,
        "results": [asdict(result) for result in results],
    }


def print_text(results: Sequence[ScanResult]) -> None:
    for result in results:
        print(f"[{result.status}] {result.target}")
        if result.version:
            print(f"  PHP: {result.version}" + (f" (fixed: {result.fixed_release})" if result.fixed_release else ""))
        if result.sapi:
            print(f"  SAPI: {result.sapi}")
        if result.http_status is not None:
            print(f"  HTTP: {result.http_status} {result.final_url or ''}".rstrip())
        print(f"  {result.summary}")
        for item in result.evidence:
            print(f"  Evidence: {item}")
        if result.mitigations:
            print("  Partial mitigations:")
            for name, check in result.mitigations.items():
                if name == "notice":
                    continue
                if isinstance(check, dict):
                    mark = "yes" if check.get("present") else "no"
                    print(f"    {name}: {mark}")
        if result.error:
            print(f"  Error: {result.error}")
        print()


def exit_code(results: Sequence[ScanResult]) -> int:
    if any(result.status in {"AFFECTED", "LIKELY_AFFECTED"} for result in results):
        return 1
    if any(result.status not in {"PATCHED"} for result in results):
        return 2
    return 0


def read_targets(positional: Sequence[str], input_file: Optional[str]) -> List[str]:
    targets = list(positional)
    if input_file:
        for line in Path(input_file).read_text(encoding="utf-8-sig").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                targets.append(stripped)
    return list(dict.fromkeys(targets))


def write_report(results: Sequence[ScanResult], output_format: str, output: Optional[str]) -> None:
    document = report_document(results)
    if output_format == "json":
        rendered = json.dumps(document, indent=2, sort_keys=True)
        if output:
            Path(output).write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
    else:
        print_text(results)
        if output:
            Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"JSON report written to {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safe checker for the PHP critical RCEs disclosed on 2026-10-21.",
        epilog="Exit codes: 0=all patched, 1=affected/likely affected, 2=inconclusive/error.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help="Assess one or more PHP version strings offline.")
    version_parser.add_argument("versions", nargs="+")

    local_parser = subparsers.add_parser("local", help="Inspect one or more local PHP executables.")
    local_parser.add_argument("--php", action="append", default=[], help="PHP executable/path; repeat for multiple runtimes.")
    local_parser.add_argument("--timeout", type=float, default=10.0)
    local_parser.add_argument("--format", choices=["text", "json"], default="text")
    local_parser.add_argument("--output", help="Write the full JSON report to this file.")

    url_parser = subparsers.add_parser("url", help="Safely fingerprint authorized HTTP(S) targets.")
    url_parser.add_argument("targets", nargs="*", help="URL or hostname. Hostnames without a scheme use HTTPS.")
    url_parser.add_argument("--input", help="Text file containing one target per line.")
    url_parser.add_argument("--authorized", action="store_true", help="Confirm you own or are authorized to assess the targets.")
    url_parser.add_argument("--header", action="append", default=[], help="Add a request header (NAME: VALUE).")
    url_parser.add_argument("--timeout", type=float, default=10.0)
    url_parser.add_argument("--workers", type=int, default=5)
    url_parser.add_argument("--proxy", help="HTTP proxy URL, for example http://127.0.0.1:8080.")
    url_parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation.")
    url_parser.add_argument("--format", choices=["text", "json"], default="text")
    url_parser.add_argument("--output", help="Write the full JSON report to this file.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        results = []
        for raw in args.versions:
            assessment = assess_version(raw)
            results.append(
                ScanResult(
                    target=raw,
                    mode="version",
                    status=assessment.status,
                    summary=assessment.summary,
                    version=assessment.version,
                    fixed_release=assessment.fixed_release,
                    details={"vendor_backport_possible": assessment.vendor_backport_possible},
                )
            )
        print_text(results)
        return exit_code(results)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    if args.command == "local":
        binaries = args.php or ["php"]
        results = [scan_local(binary, args.timeout) for binary in binaries]
        write_report(results, args.format, args.output)
        return exit_code(results)

    if not args.authorized:
        parser.error("URL mode requires --authorized to confirm target authorization")
    targets = read_targets(args.targets, args.input)
    if not targets:
        parser.error("provide at least one URL/hostname or --input file")
    if len(targets) > 1000:
        parser.error("a single run is limited to 1000 targets")
    if not 1 <= args.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    try:
        extra_headers = parse_headers(args.header)
    except ValueError as exc:
        parser.error(str(exc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_url, target, args.timeout, args.insecure, args.proxy, extra_headers)
            for target in targets
        ]
        results = [future.result() for future in futures]
    write_report(results, args.format, args.output)
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
