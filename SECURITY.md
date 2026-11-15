# Security policy

## Responsible use
CyberRed is for systems you own or are **explicitly authorized in writing** to test: your own labs, intentionally vulnerable targets, CTF platforms (within their rules) and contracted engagements. Do not use it against anyone else. Unauthorized access may be a crime in your jurisdiction.

## Reporting a vulnerability in CyberRed itself
Please report privately (GitHub Security Advisories on the published repository once it exists) rather than in a public issue. Of particular interest:
- Any way to make a tool touch a target the scope file excludes (scope-engine bypass, DNS rebinding, redirect or URL-parsing tricks).
- Any way to skip the approval gate, exceed a tier's policy, or run an arbitrary command or flag.
- Prompt-injection from target content that changes behaviour outside the model's tool permissions.
- Audit-log tampering that `verify-log` fails to detect, or secrets leaking into logs/reports.
- Unsafe handling of tool output (parser crashes, path traversal in workspace writes).

## Threat model, in brief
- **Trusted:** the operator, `scope.yaml`, the harness code.
- **Untrusted:** the LLM's output and **everything derived from targets** (banners, HTML, files, error text). The model can only *propose* typed tool calls; the executor validates, scope-checks, applies tier policy and approval, and logs each one.
- **Out of scope for the tool's guarantees:** a malicious operator, a compromised host or Docker daemon, and tool-internal vulnerabilities in third-party binaries (nmap, nuclei, …).

## Known limitations
See *Known limitations* in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#0-as-built-deviations-and-known-limitations).
