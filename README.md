# PHP critical RCE exposure checker — 21 October 2026

This is a non-destructive checker for **CVE-2026-109618** and
**CVE-2026-109619**. It does not reproduce either vulnerability and never sends
an exploit payload.

The PHP project fixed the issues in:

- PHP 8.2.35
- PHP 8.3.36
- PHP 8.4.27
- PHP 8.5.12
- PHP 8.6.0 RC4 (for prerelease testing only)

PHP 8.1 and older are end-of-life upstream. A distribution or LTS vendor may
have backported the fixes without changing the upstream-looking version, so
verify the package advisory before treating an older branch as safe.

Official references:

- [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

## Fastest reliable check: run locally

Run this on each PHP host/container:

```powershell
python .\php_critical_scan.py local
```

If multiple PHP binaries are installed:

```powershell
python .\php_critical_scan.py local --php C:\php\php.exe --php C:\legacy-php\php.exe
```

On Linux/macOS:

```bash
python3 ./php_critical_scan.py local --php /usr/bin/php
```

The local check reads the PHP version, SAPI, loaded `php.ini`, and the settings
named in the official mitigation guidance. It does not change configuration.

## Safe URL inventory

Only scan systems you own or are authorized to assess:

```powershell
python .\php_critical_scan.py url https://site1.example https://site2.example --authorized
```

For a target list and a JSON evidence file:

```powershell
python .\php_critical_scan.py url --input .\targets.example.txt --authorized --output .\php-rce-scan.json
```

To inspect the request in Burp:

```powershell
python .\php_critical_scan.py url https://site.example --authorized --proxy http://127.0.0.1:8080 --insecure
```

URL mode sends one ordinary `GET` per supplied URL and reads at most 128 KiB.
It checks version disclosures in normal response headers/body and a PHP session
cookie. If the version is hidden, the result is `PHP_VERSION_HIDDEN` or
`INCONCLUSIVE`, not "safe".

Authenticated inventory is supported with a request header. Headers are never
included in the report:

```powershell
python .\php_critical_scan.py url https://internal.example --authorized --header "Authorization: Bearer REDACTED"
```

## Offline version check

```powershell
python .\php_critical_scan.py version 8.2.34 8.2.35 8.5.11 8.5.12
```

Exit codes are suitable for automation: `0` means all assessed versions are
patched, `1` means affected/likely affected, and `2` means inconclusive/error.

## Burp passive check

Import `burp/php-critical-rce-version.bcheck` into Burp Suite Professional:

1. Go to **Extensions > BChecks**.
2. Select **Import** and choose the `.bcheck` file.
3. Browse or scan authorized applications normally.

The BCheck is passive. It reports a high-severity issue only when an affected
version is disclosed, and an informational issue when it sees PHP evidence but
cannot determine the version.

## Interpreting results

- `PATCHED`: detected version meets the official fixed threshold.
- `AFFECTED`: detected supported-branch version is below the fixed threshold.
- `LIKELY_AFFECTED`: end-of-life upstream branch; verify an explicit vendor
  backport or upgrade.
- `PHP_VERSION_HIDDEN`: PHP evidence exists but a local/package check is needed.
- `INCONCLUSIVE`: the response does not reveal enough information.
- `ERROR`: the target/runtime could not be checked.

The official configuration mitigations reduce specific attack paths but do not
make an affected runtime safe. Patch first. Apache `mod_php` is the highest-risk
SAPI identified in the PHP advisory.
