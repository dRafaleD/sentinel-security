# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | No        |

## Reporting a vulnerability

If you believe you have found a security issue in **macb-timeline** (for example memory unsafety in the TSK FFI layer, command injection, or unexpected privilege behavior), please **do not** open a public GitHub issue.

Use [GitHub Security Advisories](https://github.com/dRafaleD/sentinel-security/security/advisories/new) so the report stays private until a fix is available.

Include:

- Affected version or commit
- Environment (OS, `libtsk` version if relevant)
- Steps to reproduce and expected vs actual behavior
- Whether you have a patch or workaround

You should receive an acknowledgement within **7 days**. If the report is confirmed, we will work on a fix and coordinate disclosure.

## Scope

In scope:

- Crashes, panics, or memory unsafety in default or `--features tsk` builds
- Path handling that could write output outside the intended `-o` destination when used as documented
- Dependency issues that affect this repository’s published crates/binaries

Out of scope:

- Using the tool on systems or images without authorization
- Findings that require a malicious disk image solely to confuse forensic interpretation (false positives in anomaly rules)
- Issues in upstream **The Sleuth Kit** / `libtsk` unless they are triggered by our FFI usage in a clearly unsafe way

## Hardening notes for operators

- Run scans only on evidence you are authorized to process.
- Prefer read-only mounts and copies of disk images; never commit case data (`*.dd`, `*.E01`, and similar are gitignored).
- The TSK bindings use `unsafe` FFI. Keep `libtsk` updated through your distro packages.
- Live scanning follows the permissions of the calling user; permission-denied paths are skipped, not escalated.
