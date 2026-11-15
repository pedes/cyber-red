# ADR-0001: Provider-agnostic LLM layer

- **Status:** Proposed
- **Date:** 2026-11-15

## Context
CyberRed is a public open-source project for labs and CTFs. Users have very different access to models: some have frontier API keys, some use cheap hosted inference, and many want to run local models for privacy or cost. Tying the project to a single vendor SDK would exclude much of the audience and make benchmarking across models impossible.

## Decision
Define a **small internal LLM interface** (normalized messages, tool definitions, tool calls, usage) and implement **adapters** behind it:

1. `openai_compatible` first. It covers the largest number of providers and local servers.
2. `anthropic` native adapter.
3. Others (Gemini, etc.) as needed; an optional `litellm` adapter for long-tail providers.

Include a **JSON-protocol fallback** for models without native tool calling, and a per-model **capability profile** so the harness can adapt (context size, tool support, output limits).

## Alternatives considered
| Option | Pros | Cons |
|---|---|---|
| Single vendor SDK | Simplest | Vendor lock-in; contradicts project goal |
| LiteLLM as the core | Many providers instantly | Large dependency surface; its abstractions leak into core; harder to control tool-call normalization |
| LangChain / similar framework | Ecosystem | Heavy, frequent breaking changes, obscures agent loop we want to own |
| **Own thin interface + adapters** | Full control, small surface, easy to test and mock | We maintain adapters (mitigated by OpenAI-compatible coverage) |

## Consequences
- The core agent loop and policy engine never import a vendor SDK.
- Adding a provider means adding one adapter file plus tests.
- The benchmark suite can compare models fairly through the same harness.
- We must keep the tool-calling normalization well tested across adapters.
