# CyberRed: Product Plan

_Last updated: 2026-11-15 · Status: M1–M3 implemented (alpha), M4 partial, M5 partial. See the status legend in §7._

## 1. Vision

An open-source offensive-security agent that anyone can run against their labs and CTF targets with **whatever LLM they have access to**: a frontier API, a cheap hosted model, or a local model on their own GPU. CyberRed provides the harness (workflow, tools, safety, memory, reporting); the model provides the reasoning.

## 2. Target users

| User | Needs |
|---|---|
| **Students & CTF players** | Learn methodology, get unstuck, generate write-ups |
| **Home-lab / homelab security hobbyists** | Assess their own networks and self-hosted apps |
| **Bug bounty hunters** *(later)* | Recon automation within program scope |
| **Pentesters** *(later)* | Speed up the repetitive phases of authorized engagements |

## 3. Goals & non-goals

### Goals
1. **Provider-agnostic:** first-class support for any LLM through a thin adapter layer (see [ADR-0001](adr/0001-provider-agnostic-llm-layer.md)).
2. **Network infra + web apps** as the MVP attack surface.
3. **Safe by construction:** scope and risk policy enforced in code, independent of model behavior.
4. **Reproducible:** every action logged; every finding backed by evidence.
5. **Extensible:** adding a new tool or provider is a small, well-documented change.
6. **Measurable:** a benchmark suite of lab targets to compare models and track regressions.

### Non-goals (for now)
- Malware, C2, persistence, or EDR/AV evasion.
- Denial-of-service or destructive testing.
- Social engineering / phishing.
- Cloud-provider control-plane attacks (AWS/Azure/GCP IAM). Possible later.
- Multi-user SaaS. CyberRed is a local CLI tool.

## 4. Operating modes

| Mode | Intended for | Default autonomy |
|---|---|---|
| `lab` | Your own lab network / vulnerable VMs | Active tools auto-run, intrusive tools need approval |
| `ctf` | CTF / HTB / THM targets | Can be set to full autonomy for in-scope targets |
| `engagement` | Authorized client tests | Active tools need confirmation, intrusive tools need per-action approval, authorization reference required |

## 5. Capabilities (MVP focus: network + web)

Each tool is assigned a **risk tier**, and the policy engine decides what is allowed per mode.

| Tier | Meaning | Examples |
|---|---|---|
| **T0 Passive** | No packets sent to the target | CT logs, DNS lookups via public resolvers, CVE/exploit-db lookup, reading prior output |
| **T1 Active** | Non-destructive probing | nmap service scan, httpx, whatweb, rate-limited ffuf, non-intrusive nuclei templates |
| **T2 Intrusive** | Could change state or trip defenses | Credential brute force, sqlmap, intrusive nuclei templates, exploit PoCs |
| **T3 Forbidden** | Never available | DoS, destructive payloads, out-of-scope targets |

### 5.1 Engagement setup
- Load and validate `scope.yaml` (targets, exclusions, mode, time window, allowed tiers, rate limits).
- Show a pre-flight summary the user must confirm.
- Detect lab VPN interface (HTB/THM `tun0`) and warn if the targets aren't reachable.

### 5.2 Network infrastructure
- Host discovery (ICMP/ARP/TCP ping) across in-scope CIDRs.
- Port scanning (nmap; optional masscan/rustscan for speed) with rate limits.
- Service & version detection, OS fingerprinting.
- Protocol-specific enumeration: SMB (shares, null sessions), FTP (anon login), SSH (auth methods, banner), SNMP, LDAP, RDP, DNS (zone transfer), SMTP, NFS.
- Map versions to CVEs, and look up public exploits (searchsploit).
- Default/weak credential checks (T2, approval-gated).

### 5.3 Web applications
- HTTP probing & tech fingerprinting (httpx, whatweb).
- Content discovery: directories, files, vhosts, parameters (ffuf).
- Vulnerability scanning with nuclei (template selection by detected tech).
- Targeted checks: SQLi (sqlmap, T2), XSS, SSRF, LFI/path traversal, IDOR, auth/session issues, exposed admin panels, misconfigurations (headers, TLS, CORS).
- Screenshotting for the report (gowitness or a headless browser).

### 5.4 Exploit validation (approval-gated)
- Confirm a finding with the **least invasive** proof possible (e.g., read `/etc/passwd`, not drop a shell, unless in `ctf` mode).
- Optional Metasploit integration via RPC (later milestone).
- In `ctf` mode: capture shells, enumerate privilege-escalation paths (linpeas/winpeas), detect flags.

### 5.5 CTF & lab features
- **Flag detection:** configurable regex (e.g., `HTB\{.*?\}`, `flag\{.*?\}`, 32-hex user/root flags).
- **Write-up generator:** a narrative of how the box was solved, from the audit log.
- **Hint mode:** the agent suggests the next step but doesn't execute it (learning mode).

### 5.6 Reporting
- Findings with title, severity (CVSS 3.1/4.0), affected asset, evidence, reproduction steps, remediation, and MITRE ATT&CK technique.
- Output: Markdown (MVP), then HTML/PDF and JSON (machine-readable).
- Report is generated from the findings store and audit log, not just the model's memory.

## 6. Guardrails (core features, not add-ons)

1. **Scope engine:** every tool invocation's target arguments are parsed and checked against the allowlist and denylist. Hostnames must resolve to in-scope IPs. Exclusions always win.
2. **Network egress control:** the sandbox container's outbound traffic is restricted to in-scope ranges where possible (defense in depth).
3. **Risk-tier policy:** per-mode rules decide auto-run, confirm, or deny.
4. **Human approval gate:** an interactive prompt shows the exact command, target, and reason before T2 actions.
5. **Rate limiting:** global and per-target request/packet budgets.
6. **Kill switch:** `Ctrl-C` / `cyberred stop` terminates all running tool processes immediately.
7. **Audit log:** an append-only JSONL file of every LLM call, tool call, decision, and output hash.
8. **Prompt-injection resistance:** all target-derived content (banners, HTML, files) is treated as untrusted data. Policy is enforced outside the model, so a malicious page can't talk the agent out of scope.
9. **Secrets handling:** discovered credentials stored encrypted, redacted from logs and LLM context unless needed.
10. **Time window:** actions outside the scope's allowed window are blocked.

## 7. Roadmap & status

Legend: ✅ implemented and covered by tests · 🟡 implemented but **not verified against the real external tool / provider** · ⬜ not started

### M0: Planning ✅
- [x] Name `cyber-red` / CyberRed · plan · architecture · ADR-0001
- [x] Open decisions D1, D2, D4, D5 resolved by implementation (see §9)
- [ ] D3 license, D6 PyPI name, D7 supported-model tier still open
- [ ] Publish GitHub repo, add LICENSE, CODE_OF_CONDUCT.md

### M1: Foundation ✅ (🟡 for Docker)
- [x] CLI: `init`, `run`, `status`, `report`, `stop`, `verify-log`, `scope-check`, `tools`, `doctor`, `demo`
- [x] `scope.yaml` schema (strict: unknown keys are errors) and validation
- [x] Scope engine + policy engine with extensive tests (bypass attempts, rebinding, redirects)
- [x] LLM layer: OpenAI-compatible adapter, Anthropic adapter, JSON tool-calling fallback, mock provider
- [x] Sandbox runner: native ✅ · Docker 🟡 (image never built)
- [x] Hash-chained audit log + SQLite findings store
- Exit criterion "refuses an out-of-scope target using two different providers": ✅ shown with the mock provider and a fake OpenAI-compatible server (native + JSON fallback). 🟡 not yet with live provider APIs.

### M2: Network infrastructure ✅ / 🟡
- [x] Pure-Python TCP connect scanner with banner fingerprinting and version→CVE hints
- [x] FTP anonymous login, Redis/memcached/Elasticsearch exposure, TLS inspection
- 🟡 nmap discovery/service scan, safe and intrusive NSE script sets, XML parsing, searchsploit
- ⬜ UDP/SNMP, SMB null-session depth beyond NSE, AD enumeration

### M3: Web applications ✅ / 🟡
- [x] `http_probe`, `web_common_files`, `web_crawl`, `web_param_probe` (pure Python)
- [x] Tech-aware nuclei tag selection in the playbook
- 🟡 `ffuf_discover`, `nuclei_scan`(+intrusive), `sqlmap_test`
- ⬜ Benchmark against Juice Shop / DVWA (exit criterion not yet measured)

### M4: Exploit validation & CTF mode (partial)
- [x] Approval-gate UX, least-invasive validation (reflection/SQL-error signals; sqlmap detection-only)
- [x] CTF mode: flag detection, write-up generator, hint mode
- ⬜ Shell capture, privilege-escalation enumeration, Metasploit RPC (deliberately deferred)

### M5: Reporting & benchmarks (partial)
- [x] Markdown / JSON / write-up reports with ATT&CK mapping and CVSS estimates
- ⬜ PDF/HTML export · ⬜ benchmark suite and model leaderboard · ⬜ docs site / demo video

### Later (v0.2+)
Active Directory module · Metasploit RPC · MCP server exposing the scoped tool registry · plugin system · local web dashboard · pause/resume · container egress restriction · encrypted credential vault · optional cheaper "summarizer" model role

## 8. Success metrics
- **Benchmark solve rate** per model on the lab suite (primary quality metric).
- **Zero scope violations** in tests and benchmarks (hard requirement).
- Time-to-first-finding on standard lab targets.
- Community: stars, contributors, providers/tools added by the community.

## 9. Open decisions

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Language | Python · Go · TypeScript | ✅ **Python** (implemented, ≥3.10) |
| D2 | LLM abstraction | Own thin interface · LiteLLM · LangChain | ✅ **Own thin interface** (ADR-0001); LiteLLM adapter not built |
| D3 | License | Apache-2.0 · MIT · GPL-3.0 · AGPL-3.0 | **Open: needs your decision.** Apache-2.0 (permissive + patent grant) or GPL-3.0 (keeps forks open) |
| D4 | Tool execution | Docker sandbox · native host | ✅ Docker preferred when usable, native fallback (`--runner`) |
| D5 | Models without native tool calling | Require tool calling · JSON-mode fallback | ✅ JSON fallback implemented (`--no-native-tools`) |
| D6 | Package name | `cyberred` on PyPI (check availability) | Reserve early |
| D7 | Minimum model capability | Define a "supported" tier from benchmark results | Decide after M3 benchmarks |
