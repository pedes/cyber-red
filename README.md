# 🛡️ CyberRed

> An open-source, **LLM-provider-agnostic** offensive-security agent for **labs, CTFs and authorized penetration testing**.

**Status: alpha (`0.1.0.dev0`).** The core harness works end to end and is covered by 116 tests, but the external-tool wrappers (nmap, nuclei, ffuf, sqlmap, searchsploit) and the Docker image have **not yet been run against the real binaries**. See [what's verified](#whats-verified-and-whats-not).

CyberRed drives real security tooling through a structured methodology (**scope → recon → enumeration → vulnerability discovery → validation → report**) and enforces its safety rules **in code**, not in a prompt.

- 🔌 **Bring any model.** One thin interface, adapters for OpenAI-compatible endpoints (OpenAI, Ollama, vLLM, LM Studio, OpenRouter, Groq, …) and Anthropic, plus a JSON tool-calling fallback for models without function calling. Or use **no LLM at all**: the built-in playbook runs the same methodology.
- 🧰 **Works out of the box.** Port scanning, HTTP probing, TLS, FTP and exposed-service checks, exposed-file discovery, crawling and light input testing are pure Python. nmap, nuclei, ffuf, sqlmap and searchsploit are used automatically when installed.
- 🧠 **Smart, not noisy.** A deterministic playbook decides the next best step from what has been learned (open SMB → SMB checks; web → fingerprint → exposed files → crawl → tech-aware nuclei tags). It never repeats work, and its suggestions are fed to the LLM each turn so even small local models follow a sound plan.
- 🔐 **Safe by construction.** Scope engine, risk tiers, approval gates, rate limits, kill switch, hash-chained audit log, and target output treated as untrusted data.
- 🚩 **Lab and CTF native.** Flag detection, write-up generation, hint mode.

## Quick start

```bash
git clone <this repo> && cd cyber-red
uv venv --python 3.12 && uv pip install -e ".[dev]"      # or: python -m venv .venv && pip install -e ".[dev]"
source .venv/bin/activate

cyberred demo        # see it work against a built-in simulated vulnerable app on 127.0.0.1, no setup
cyberred doctor      # what's installed: Docker, nmap, nuclei, ffuf, sqlmap, API keys
```

### Run an engagement

```bash
cyberred init -t 10.10.11.0/24 -t target.htb --mode ctf     # writes scope.yaml
cyberred scope-check scope.yaml 10.10.11.7 8.8.8.8          # test the scope, sends no traffic

cyberred run scope.yaml --autopilot            # built-in playbook, no LLM needed
cyberred run scope.yaml --autopilot --hint     # learning mode: show what it would do, execute nothing
```

### Use an LLM (any provider)

```bash
# Local model via Ollama
cyberred run scope.yaml --provider openai_compatible --base-url http://localhost:11434/v1 --model qwen2.5:14b

# Hosted, OpenAI-compatible (the key is read from an env var, never from a file)
export OPENAI_API_KEY=...
cyberred run scope.yaml --provider openai_compatible --model gpt-4o-mini --api-key-env OPENAI_API_KEY

# Anthropic
export ANTHROPIC_API_KEY=...
cyberred run scope.yaml --provider anthropic --model <model-id>

# Model without function calling: tool calls travel as JSON text
cyberred run scope.yaml --provider openai_compatible --base-url http://localhost:8080/v1 --model small --no-native-tools
```

Or put an `llm:` block in `scope.yaml` ([example](examples/scope.example.yaml)). Add `price_in_per_mtok` / `price_out_per_mtok` to enforce a cost budget.

### After a run

```bash
cyberred status  workspaces/<engagement>                 # hosts, findings, flags
cyberred report  workspaces/<engagement> -f md -o r.md   # md | json | writeup (CTF-style narrative)
cyberred verify-log workspaces/<engagement>              # prove the audit log wasn't edited
cyberred stop    workspaces/<engagement>                 # kill switch for a running engagement (or Ctrl-C)
```

## What it can do

| Phase | Tools (pure Python unless noted) |
|---|---|
| **Recon** | `dns_lookup` · `tcp_port_scan` (connect scan + banner fingerprinting) · `nmap_scan` *(nmap)* |
| **Enumeration** | `ftp_anon_check` · `exposed_service_check` (Redis / memcached / Elasticsearch) · `tls_inspect` · `nmap_scripts` *(safe NSE: SMB, SMTP, LDAP, NFS, RDP, …)* · `http_probe` · `web_common_files` · `web_crawl` · `ffuf_discover` *(ffuf)* |
| **Vuln discovery** | built-in version→CVE hints · `searchsploit_lookup` *(searchsploit)* · `nuclei_scan` *(nuclei, tech-aware tags)* |
| **Validation (T2, approval-gated)** | `web_param_probe` (reflection + SQL-error signals) · `sqlmap_test` *(detection only)* · `nmap_scripts_intrusive` · `nuclei_scan_intrusive` |
| **Reporting** | Markdown / JSON / CTF write-up, with CVSS estimates and MITRE ATT&CK mapping |

Notable checks: exposed `.git` / `.env` / backups (with soft-404 detection and secret masking), missing security headers, risky cookies, reflective CORS, cleartext login forms, dangerous HTTP methods, directory listing, anonymous FTP, unauthenticated Redis/Elasticsearch/memcached, expired/self-signed/deprecated TLS, and version-based hints (vsFTPd 2.3.4, Apache 2.4.49/50, ProFTPD 1.3.5, Samba, Exim, OpenSSH, EOL PHP/Tomcat/Apache 2.2). Version-only matches are always recorded as **candidates**, because distro back-ports mean a banner can lie.

## Safety model

| Control | How it works |
|---|---|
| **Scope engine** | Every target is parsed, resolved and checked **before** a tool runs. Exclusions always win; hostnames must resolve inside scope; resolution is pinned for the engagement; userinfo tricks, obfuscated IPs, `..` and encoded traversal are rejected; web redirects are re-checked at every hop; the connected peer address is compared to the pinned resolution. |
| **Risk tiers** | T0 passive · T1 active, non-destructive · T2 intrusive (needs approval) · T3 forbidden (cannot be registered). Per-mode defaults; `engagement` mode can only be *tightened* by config. |
| **Approval gate** | T2 always asks (`--yes` auto-approves only in `lab`/`ctf` mode). "Always allow" is never offered for T2. Non-interactive sessions deny. |
| **No raw shell** | The model fills typed parameters. Commands are argv lists (never a shell); values can't start with `-`; dangerous switches (sqlmap `--os-shell`/`--dump`, brute-force NSE scripts, …) are simply not exposed. |
| **Untrusted output** | Everything derived from a target is fenced in `<tool_output>` and the model is told to treat it as data. Policy lives outside the model, so injected text cannot widen scope. |
| **Kill switch** | Ctrl-C (or `cyberred stop`) kills tool process groups / containers immediately. |
| **Audit log** | Append-only JSONL, hash-chained, secrets redacted. Reports are generated from it and the findings database, not from model memory. |
| **Budgets & rate limits** | Steps, cost, wall-clock, packets/s and HTTP requests/s. |
| **Time window** | Optional start/end enforced for every call. |

## What's verified, and what's not

**Verified by the test suite (116 tests):** scope parsing and bypass attempts, policy/approval rules, kill switch, prompt-injection containment, audit-chain tamper detection, both LLM adapters (against mock servers, including retries and the JSON fallback), the agent loop and context compaction, the playbook, all pure-Python tools against a local simulated target, the report renderers, the CLI, and the process runner (timeouts, process-group kill, no shell interpretation).

**Not yet verified:**
- ❗ The wrappers for **nmap, nuclei, ffuf, sqlmap and searchsploit** have only been tested against sample output and a fake runner, not the real binaries.
- ❗ The **Docker image** (`docker/Dockerfile`) and the **lab compose file** have never been built or started (Docker wasn't available where this was developed).
- ❗ **No real LLM provider** has been exercised; adapters are tested against wire-format mocks. Small-model behaviour is unmeasured; the planned benchmark suite doesn't exist yet.
- Not implemented: exploitation / post-exploitation (shells, privilege escalation, Metasploit, Active Directory), UDP scanning, PDF reports, resuming a stopped engagement, container egress restriction, an encrypted credential vault.

See [docs/PLAN.md](docs/PLAN.md) for the roadmap and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Responsible use

Only test systems you own or have **explicit, written authorization** to test: your own lab, intentionally vulnerable targets (OWASP Juice Shop, DVWA, Metasploitable), CTF platforms within their rules, or contracted engagements. Unauthorized testing may be illegal. The authors accept no liability for misuse. See [SECURITY.md](SECURITY.md).

## License

Not yet chosen (see open decision D3 in the plan). Until a `LICENSE` file is added, all rights are reserved.
