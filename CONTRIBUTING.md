# Contributing

Thanks for helping. CyberRed is an offensive-security tool, so a few extra rules apply on top of the usual ones.

## Setup
```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"   # or python -m venv + pip install -e ".[dev]"
ruff check src tests && pytest
```
`cyberred demo` runs the whole pipeline against a built-in simulated target with no setup.

## Ground rules
- **Authorized targets only.** Develop and test against your own lab or the simulated demo target (`cyberred.demo`). Never include real third-party hosts in tests, fixtures, docs or issues.
- **Safety is enforced in code.** No change may let a model widen scope, skip approval, or run an unvalidated command. Anything touching `policy/`, `core/executor.py` or `tools/base.py` needs tests for the bypass it must prevent.
- **No T3 tools.** No DoS, destructive actions, persistence, malware/C2 or detection evasion. No tool that accepts a raw shell string or arbitrary flags.
- **Detection over exploitation.** Prefer the least invasive proof. Intrusive behaviour must be tier T2 (approval-gated).
- **Candidates vs confirmed.** Version-only or heuristic matches are `status="candidate"`. Only mark `confirmed` on direct evidence.

## Adding a tool
1. Define it in `src/cyberred/tools/` with typed `Param`s (patterns, enums, max lengths), a tier, phases and `target_args` for **every** parameter that names a target (that is what routes it through the scope engine).
2. External binary? Build an **argv list**, list it in `requires`, add a parser in `parsers/` returning `{hosts, services, endpoints, findings}`.
3. Put secrets in neither evidence nor logs (mask values, as `.env` handling does).
4. Tests: validation edge cases, a scope-block case, parser fixtures, and (for pure-Python tools) a behaviour test against the demo server. Update `core/playbook.py` if the tool should be suggested automatically.

## Adding an LLM provider
Implement `llm.base.Provider.complete` (normalized messages, tool calls and usage). OpenAI-compatible servers need no code, only config. Add a wire-format test with `httpx.MockTransport`.

## Pull requests
Keep them focused, include tests, run `ruff check` and `pytest`, and describe any change to the safety model explicitly.
