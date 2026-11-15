# CyberRed: Architecture

_Status: v0.1 alpha. The design below is implemented except where the **As built** notes say otherwise._

## 0. As built: deviations and known limitations

**Deviations from the original design**
- Tools are **Python definitions** (`tools/*.py`), not YAML, so each can validate typed parameters and build argv safely. A YAML loader may come later.
- Several tools are **pure Python** (port scan, HTTP probe, TLS, FTP, exposed-service checks, crawl, param probe) so the agent is useful with zero external binaries.
- A **playbook** (`core/playbook.py`) was added: a deterministic next-step engine. It runs the autopilot (no LLM) and supplies the LLM with ready-to-use suggestions each turn. It normalises arguments through each tool's own validator so completed, failed and declined steps are never re-suggested.
- The **executor** (`core/executor.py`) is the single pipeline every call passes through: validate → scope → policy → dedupe → approval → run → ingest → flag scan → audit.
- The kill switch is a `threading.Event` (loop-agnostic, signal-safe), polled while tools run; the runner also kills process groups / containers.
- `scope.hosts` pins name→IP (CTF vhosts) and is passed to Docker as `--add-host`.

**Known limitations**
- DNS pinning is enforced for in-process HTTP tools (peer-address check after connect). External binaries (nuclei, ffuf, sqlmap) resolve names themselves; under Docker the pinned map is injected via `--add-host`, natively there is a small TOCTOU window.
- Container **egress restriction** (defense in depth behind the scope engine) is not implemented.
- No encrypted credential vault yet (no tool captures credentials in v0.1).
- The optional "summarizer" model role and pause/resume are not implemented. Context is kept small by compaction and a regenerated STATE block instead.
- External-tool wrappers and the Docker image are untested against real binaries (see README).


## 1. High-level overview

```
                         ┌──────────────────────────────┐
   user ──── CLI ───────▶│        Orchestrator          │◀──── scope.yaml / config
                         │  (phase state machine +      │
                         │   planning LLM loop)         │
                         └───────┬──────────────┬───────┘
                                 │ delegates    │ LLM calls
                ┌────────────────┼──────┐       ▼
                ▼                ▼      ▼   ┌──────────────────────┐
          ┌──────────┐   ┌──────────┐ ┌─────┤  LLM Provider Layer   │
          │  Recon   │   │   Web    │ │ ... │  (adapters: OpenAI-   │
          │specialist│   │specialist│ │     │  compatible, Anthropic│
          └────┬─────┘   └────┬─────┘ │     │  Gemini, LiteLLM...)  │
               │ tool calls   │       │     └──────────────────────┘
               ▼              ▼       ▼
          ┌─────────────────────────────────┐
          │          Tool Registry          │  typed schemas + risk tier
          └───────────────┬─────────────────┘
                          ▼
          ┌─────────────────────────────────┐
          │   Policy Engine (enforced)      │  scope ✓ tier ✓ rate ✓ time ✓
          │   └─ Approval Gate (human)      │
          └───────────────┬─────────────────┘
                          ▼
          ┌─────────────────────────────────┐        ┌──────────────┐
          │   Sandbox Runner (Docker/Kali)  │───────▶│   Targets    │
          │   egress limited to scope       │        │ (lab / CTF)  │
          └───────────────┬─────────────────┘        └──────────────┘
                          ▼
          ┌─────────────────────────────────┐
          │ Output Parsers → Findings Store │  SQLite: hosts, services,
          │ (structured, summarized)        │  vulns, creds, evidence
          └───────────────┬─────────────────┘
                          ▼
          ┌──────────────────┐   ┌──────────────────┐
          │   Audit Log      │   │  Report Engine   │
          │ (append-only)    │   │ MD / JSON / PDF  │
          └──────────────────┘   └──────────────────┘
```

**Key principle:** the LLM *proposes*, the harness *disposes*. The model never executes anything directly; every action passes through the policy engine.

## 2. Components

### 2.1 LLM Provider Layer
See [ADR-0001](adr/0001-provider-agnostic-llm-layer.md).

- A single internal interface, e.g. `complete(messages, tools, options) -> Response`, with a normalized message, tool-call, and usage format.
- **Adapters:**
  - `openai_compatible`: one adapter covers OpenAI, Ollama, vLLM, LM Studio, llama.cpp server, OpenRouter, Groq, Together, and others that expose the OpenAI Chat Completions format.
  - `anthropic`: native Messages API.
  - `gemini`: native API (later).
  - `litellm` (optional): a bridge to many more providers for users who want it.
- **Model capability profile** (config or auto-detected): context window, native tool calling (yes/no), JSON mode, vision, max output tokens, cost per token.
- **Tool-calling fallback:** for models without native tool calling, a structured-JSON protocol in the prompt, validated with a schema and retried on parse errors.
- **Role-based model routing:** optionally use a strong model for the orchestrator and a cheaper or local model for summarizing tool output.
- Retries, timeouts, token/cost accounting, and streaming are handled uniformly.

### 2.2 Orchestrator
- **Phase state machine:** `setup → recon → enumeration → vuln_discovery → validation → reporting`. Phases constrain which tools are offered, which keeps small models on track.
- **Planning loop:** observe the current state (summarized from the findings store), then plan, call tools, parse output, update state, and repeat.
- **Budgets:** max steps, max tokens/cost, and max wall-clock time per engagement.
- **Delegation:** hands focused sub-tasks to specialists (e.g. "enumerate web service on 10.10.10.5:8080").

### 2.3 Specialists
Each specialist is a scoped prompt with its own subset of tools and a phase focus. MVP specialists:
- **Recon:** host discovery, port scans, service detection.
- **Network services:** protocol-specific enumeration.
- **Web:** fingerprinting, content discovery, vuln scanning.
- **Validator:** least-invasive proof of findings (T2, gated).
- **Reporter:** turns findings and evidence into a report or CTF write-up.

### 2.4 Tool Registry
Each tool is a declarative definition plus a small wrapper:

```yaml
name: nmap_service_scan
description: Detect open ports and service versions on in-scope hosts
risk_tier: T1
phases: [recon, enumeration]
target_args: [targets]          # args the scope engine must validate
parameters:                      # JSON Schema exposed to the LLM
  targets: { type: array, items: { type: string } }
  ports:   { type: string, default: "top-1000" }
command: nmap -sV -Pn -oX - {ports_flag} {targets}
parser: nmap_xml
timeout: 900
```

- The LLM never sends raw shell strings. It fills typed parameters that are validated and safely templated, which rules out shell injection.
- An optional `raw_command` tool (T2, `lab`/`ctf` only, always gated) covers power users.

### 2.5 Policy Engine & Scope Engine
Checks run in order, and any failure blocks the call:
1. **Scope:** each `target_arg` is normalized (IP/CIDR/hostname/URL), and hostnames are resolved. The target must be inside an `include` entry and outside every `exclude` entry.
2. **Tier vs. mode:** auto / confirm / deny, per the mode's policy table.
3. **Time window** and **rate budget**.
4. **Approval gate:** an interactive prompt showing the command, target, tier, and the model's stated reason. The decision is logged.

The policy engine is the most heavily tested component, with property-based tests for scope edge cases (IPv6, CIDR boundaries, DNS rebinding, URL tricks like `http://in-scope@out-of-scope`).

### 2.6 Sandbox Runner
- Tools run in a Docker container built from a Kali-based (or slim custom) image with pinned tool versions.
- Per-engagement workspace volume for outputs.
- Egress restricted with container network rules to in-scope ranges (best effort, as a second layer behind the policy engine).
- A native-host runner is available as an opt-in for users without Docker.

### 2.7 Output Parsers & Context Management
- Raw tool output is **never** dumped wholesale into the LLM context.
- Parsers convert output to structured records (nmap XML → hosts/services; nuclei JSONL → findings; ffuf JSON → paths).
- Large outputs are stored in the workspace; the model gets a summary plus a handle to query details on demand.
- All target-derived text is wrapped and labeled as **untrusted data**.

### 2.8 Findings Store
SQLite per engagement. Core entities:
`Engagement · Host · Service · WebEndpoint · Finding · Evidence · Credential (encrypted) · Flag · ToolRun`

### 2.9 Audit Log
Append-only JSONL file: timestamp, actor (model/user/system), event type, tool, args, policy decision, output hash, and token usage. It is the source of truth for reports and write-ups.

### 2.10 Report Engine
Templates (Jinja2) render the findings store and audit log into Markdown, JSON, and later HTML/PDF. Supports `pentest-report` and `ctf-writeup` templates.

## 3. Proposed repository layout (for M1)

```
cyber-red/
├── src/cyberred/
│   ├── cli/            # command-line entry points
│   ├── core/           # orchestrator, state machine, budgets
│   ├── agents/         # specialist prompts & logic
│   ├── llm/            # provider interface + adapters
│   ├── tools/          # tool definitions (YAML) + wrappers
│   ├── parsers/        # nmap, nuclei, ffuf, httpx...
│   ├── policy/         # scope engine, tiers, approval gate
│   ├── sandbox/        # docker + native runners
│   ├── store/          # SQLite models, audit log
│   └── report/         # templates & renderers
├── docker/             # tool image Dockerfile
├── lab/                # docker-compose vulnerable lab targets
├── benchmarks/         # target definitions + scoring
├── tests/
├── docs/
└── examples/
```

## 4. Extensibility
- **New tool:** add a YAML definition and, if needed, a parser. No core changes.
- **New provider:** implement the provider interface (~1 file). OpenAI-compatible providers need only config.
- **New specialist:** a prompt plus a tool subset plus phase bindings.
- **Future MCP server:** expose the tool registry (with the policy engine still enforced) to external MCP clients.

## 5. Security of CyberRed itself
- Never auto-execute code fetched from targets.
- Treat everything from targets as hostile input, including possible prompt injection.
- API keys come from env vars or the OS keychain, never written to logs or reports.
- Signed releases and a pinned tool image (supply-chain hygiene).
