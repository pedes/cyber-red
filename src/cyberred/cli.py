"""cyberred command-line interface."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml
from pydantic import ValidationError
from rich import box
from rich.prompt import Prompt
from rich.table import Table

from . import __version__, ui
from .config import SCOPE_TEMPLATE, Config, LLMRoleCfg, Tier
from .core import Agent, ApprovalRequest, Engagement, new_workspace, run_autopilot
from .policy import ScopeEngine, ScopeViolation
from .report import render_json, render_markdown, render_writeup
from .sandbox import DockerRunner, NativeRunner, select_runner
from .store import Store, verify_audit_log
from .tools import build_registry

app = typer.Typer(add_completion=False, help="CyberRed: provider-agnostic offensive-security agent for labs, CTFs and authorized testing.",
                  pretty_exceptions_show_locals=False)

WS_DEFAULT = Path(os.environ.get("CYBERRED_HOME", "workspaces"))


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, no_emoji: Annotated[bool, typer.Option("--no-emoji", help="Disable emoji in output")] = False,
         version: Annotated[bool, typer.Option("--version", help="Show version")] = False) -> None:
    if no_emoji:
        ui.set_emoji(False)
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        ui.banner(__version__)
        typer.echo(ctx.get_help())


def _load(path: Path) -> Config:
    try:
        return Config.load(path)
    except FileNotFoundError:
        ui.err(f"scope file not found: {path}  (create one with `cyberred init`)")
    except ValidationError as e:
        ui.err("invalid scope file:")
        for err in e.errors():
            ui.muted(f"  {'.'.join(str(x) for x in err['loc'])}: {err['msg']}")
    except yaml.YAMLError as e:
        ui.err(f"could not parse YAML: {e}")
    raise typer.Exit(2)


# ------------------------------------------------------------------------------------------ init

@app.command()
def init(
    target: Annotated[list[str], typer.Option("--target", "-t", help="In-scope IP, CIDR, hostname or URL (repeatable)")],
    name: Annotated[str, typer.Option(help="Engagement name")] = "my-engagement",
    mode: Annotated[str, typer.Option(help="lab | ctf | engagement")] = "lab",
    authorization: Annotated[Optional[str], typer.Option(help="Authorization reference (required for mode=engagement)")] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("scope.yaml"),
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Create a scope.yaml for a new engagement."""
    if output.exists() and not force:
        ui.err(f"{output} already exists (use --force to overwrite)")
        raise typer.Exit(1)
    if mode not in ("lab", "ctf", "engagement"):
        ui.err("mode must be lab, ctf or engagement")
        raise typer.Exit(2)
    auth = f"  authorization: \"{authorization}\"" if authorization else ("  authorization: \"<reference to written authorization>\"" if mode == "engagement" else "  # authorization: \"<reference>\"   # required for mode=engagement")
    text = SCOPE_TEMPLATE.format(name=name, mode=mode, auth_line=auth, includes="\n".join(f"    - {t}" for t in target))
    output.write_text(text)
    try:
        Config.load(output)
    except ValidationError as e:
        ui.warn(f"{output} written but needs attention: {e.errors()[0]['msg']}")
    else:
        ui.ok(f"wrote {output}")
    ui.muted("  Review it, then: cyberred run " + str(output))


# ------------------------------------------------------------------------------------------ doctor / tools

@app.command()
def doctor() -> None:
    """Check the local environment: Docker, tool binaries, API keys."""
    ui.banner(__version__)
    t = Table(box=box.SIMPLE_HEAD, header_style="muted", pad_edge=False)
    t.add_column("Check")
    t.add_column("Status")
    t.add_column("Notes", style="muted")

    def row(name: str, good: bool, note: str = "", optional: bool = False) -> None:
        mark = f"[ok]{ui.em('ok')}ok[/]" if good else ("[muted]– missing[/]" if optional else f"[warn]{ui.em('warn')}missing[/]")
        t.add_row(name, mark, note)

    row("Python ≥ 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    docker = DockerRunner.usable()
    row("Docker + cyberred/tools image", docker, "build: docker build -t cyberred/tools docker/" if not docker else "sandbox available", optional=True)
    native = NativeRunner(Path("."))
    for b, why in (("nmap", "service/version scans, NSE scripts"), ("nuclei", "template vulnerability scanning"), ("ffuf", "content discovery"),
                   ("sqlmap", "SQLi confirmation (T2)"), ("searchsploit", "Exploit-DB lookup")):
        row(f"{b} (host)", native.available(b), why, optional=True)
    for var, what in (("OPENAI_API_KEY", "OpenAI-compatible"), ("ANTHROPIC_API_KEY", "Anthropic")):
        row(var, bool(os.environ.get(var)), what, optional=True)
    ui.console.print(t)
    ui.muted("Built-in Python tools (port scan, HTTP probe, TLS, FTP, exposed-service checks) work with no extra binaries.")


@app.command()
def tools() -> None:
    """List tools, their risk tier, phases and availability."""
    reg = build_registry()
    runner = select_runner("auto", Path("."))
    t = Table(title=f"{ui.em('tool')}Tools (runner: {runner.name})", title_justify="left", box=box.SIMPLE_HEAD, header_style="muted", pad_edge=False)
    t.add_column("Tool", no_wrap=True, min_width=22)
    t.add_column("Tier", no_wrap=True, min_width=4)
    t.add_column("Ready", no_wrap=True, min_width=17)
    t.add_column("What it does", no_wrap=True, style="muted")
    room = max(24, ui.console.width - (22 + 4 + 17) - 4 * 2 - 1)  # fixed columns + padding; truncate ourselves, Rich would squash Tier
    for tool in reg.all():
        ready = all(runner.available(b) for b in tool.requires)
        first = tool.description.split(". ")[0].rstrip(".")
        first = first if len(first) <= room else first[: room - 1] + "…"
        t.add_row(tool.name, ui.tier_text(tool.tier.value),
                  "[ok]yes[/]" if ready else f"[muted]no ({', '.join(tool.requires)})[/]", first)
    ui.console.print(t)


@app.command("scope-check")
def scope_check(scope_file: Path, targets: Annotated[list[str], typer.Argument(help="Targets to test against the scope")]) -> None:
    """Test whether targets would be allowed by a scope file (no traffic is sent)."""
    cfg = _load(scope_file)
    eng = ScopeEngine(cfg.scope)
    for tgt in targets:
        try:
            r = eng.check(tgt)
            ui.ok(f"{tgt}  →  in scope  ({', '.join(r.addresses[:4])}{' …' if len(r.addresses) > 4 else ''})")
        except ScopeViolation as e:
            ui.err(f"{tgt}  →  BLOCKED: {e}")


# ------------------------------------------------------------------------------------------ run

def _build_provider(cfg: Config, provider: str | None, model: str | None, base_url: str | None,
                    api_key_env: str | None, no_native_tools: bool):
    from .llm import ProviderError, build_provider

    role = cfg.llm.orchestrator.model_copy() if cfg.llm.orchestrator else None
    if provider or model or base_url or api_key_env or no_native_tools or role is None:
        base = role or LLMRoleCfg()
        data = base.model_dump()
        for k, v in (("provider", provider), ("model", model), ("base_url", base_url), ("api_key_env", api_key_env)):
            if v:
                data[k] = v
        if no_native_tools:
            data["native_tools"] = False
        if not (role or provider or model):
            return None
        role = LLMRoleCfg.model_validate(data)
    try:
        return build_provider(role)
    except ProviderError as e:
        ui.err(str(e))
        raise typer.Exit(2) from None


def _make_approver(cfg: Config, yes: bool):
    auto = yes and cfg.engagement.mode in ("lab", "ctf")
    if yes and not auto:
        ui.warn("--yes is ignored in 'engagement' mode: approvals stay manual")

    async def approver(req: ApprovalRequest) -> str:
        ui.approval_panel(req.tool, req.tier.value, req.targets, req.reason, str({k: v for k, v in req.args.items()}))
        if auto:
            ui.muted("   auto-approved (--yes)")
            return "yes"
        if not sys.stdin.isatty():
            ui.muted("   no interactive terminal: denied")
            return "no"
        choices = ["y", "n", "a"] if req.tier in (Tier.T0, Tier.T1) else ["y", "n"]
        ans = await asyncio.get_running_loop().run_in_executor(
            None, lambda: Prompt.ask("   approve? ([y]es / [n]o" + (" / [a]lways this tool)" if "a" in choices else ")"), choices=choices, default="n"))
        return {"y": "yes", "n": "no", "a": "always"}[ans]

    return approver


def _install_signals(eng: Engagement) -> None:
    loop = asyncio.get_running_loop()

    def handler() -> None:
        if eng.stop_event.is_set():
            raise KeyboardInterrupt
        ui.warn("kill switch: stopping running tools (press Ctrl-C again to force quit)")
        eng.request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handler)
        except (NotImplementedError, RuntimeError):  # pragma: no cover - Windows
            pass


def _preflight(cfg: Config, eng: Engagement, provider_name: str) -> None:
    ui.banner(__version__)
    t = Table.grid(padding=(0, 2))
    t.add_column(style="muted")
    t.add_column(style="text")
    t.add_row("engagement", f"{cfg.engagement.name}  [muted]({cfg.engagement.mode} mode)[/]")
    for line in eng.scope.describe():
        k, _, v = line.partition(": ")
        t.add_row(k, v)
    t.add_row("runner", eng.runner.name)
    t.add_row("driver", provider_name)
    t.add_row("tiers", " ".join(f"{x.value}:{eng.policy.default_for(x)}" for x in (Tier.T0, Tier.T1, Tier.T2) if x in cfg.policy.allowed_tiers))
    t.add_row("workspace", str(eng.ws))
    ui.console.print(ui.Panel(t, title=f"{ui.em('target')}pre-flight", title_align="left", border_style="muted", box=box.ROUNDED))
    ready = [x.name for x in eng.available_tools()]
    missing = sorted({b for x in eng.registry.all() for b in x.requires if not eng.runner.available(b)})
    ui.muted(f"{len(ready)} tools ready" + (f" · not installed: {', '.join(missing)} (see `cyberred doctor`)" if missing else ""))


def _wrap_up(eng: Engagement, started: float, quiet: bool = False) -> Path | None:
    eng.finish()
    if quiet:
        return None
    st = eng.store
    ui.rule("results", "report")
    fs = st.findings()
    if st.hosts_with_services():
        ui.console.print(ui.hosts_table(st.hosts_with_services()))
    if fs:
        ui.console.print(ui.findings_table(fs[:25]))
        if len(fs) > 25:
            ui.muted(f"  … {len(fs) - 25} more in the report")
    ui.summary_panel(st.counts(), st.severity_counts(), st.counts()["flags"], st.counts()["runs"], time.monotonic() - started)
    if eng.executor.blocked_attempts:
        ui.muted(f"{ui.em('shield')}{eng.executor.blocked_attempts} out-of-scope attempt(s) were blocked and logged")
    report = eng.ws / "report.md"
    report.write_text(render_markdown(eng.ws, st))
    ui.ok(f"report: {report}")
    return report


@app.command()
def run(
    scope_file: Path,
    autopilot: Annotated[bool, typer.Option("--autopilot", help="Follow the built-in playbook with no LLM")] = False,
    aggressive: Annotated[bool, typer.Option("--aggressive", help="Allow the playbook to propose T2 (intrusive) steps; approval still applies")] = False,
    thorough: Annotated[bool, typer.Option("--thorough", help="Add full 65535-port sweeps")] = False,
    hint: Annotated[bool, typer.Option("--hint", help="Learning mode: show what it would do next, execute nothing")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Auto-approve T2 actions (lab/ctf modes only)")] = False,
    runner: Annotated[str, typer.Option(help="auto | docker | native")] = "auto",
    workspace_dir: Annotated[Path, typer.Option(help="Where engagement workspaces are created")] = WS_DEFAULT,
    provider: Annotated[Optional[str], typer.Option(help="openai_compatible | anthropic (overrides scope.yaml)")] = None,
    model: Annotated[Optional[str], typer.Option(help="Model name")] = None,
    base_url: Annotated[Optional[str], typer.Option(help="API base URL (Ollama: http://localhost:11434/v1)")] = None,
    api_key_env: Annotated[Optional[str], typer.Option(help="Name of the env var holding the API key")] = None,
    no_native_tools: Annotated[bool, typer.Option("--no-native-tools", help="Use JSON tool protocol for models without function calling")] = False,
    goal: Annotated[str, typer.Option(help="Custom objective for the agent")] = "",
    max_steps: Annotated[Optional[int], typer.Option(help="Override the step budget")] = None,
) -> None:
    """Run an engagement against the targets in SCOPE_FILE."""
    cfg = _load(scope_file)
    if max_steps:
        cfg.budgets.max_steps = max_steps
    llm = None if autopilot else _build_provider(cfg, provider, model, base_url, api_key_env, no_native_tools)
    if llm is None and not autopilot:
        ui.info("no LLM configured → running the built-in playbook (use --provider/--model, or an `llm:` block, for the agent)", "hint")
    try:
        eng = Engagement(cfg, new_workspace(workspace_dir, cfg.engagement.name), runner, _make_approver(cfg, yes), hint)
    except RuntimeError as e:
        ui.err(str(e))
        raise typer.Exit(2) from None
    started = time.monotonic()
    _preflight(cfg, eng, f"{llm.name} · {llm.model}" if llm else "playbook (no LLM)")

    async def go() -> None:
        _install_signals(eng)
        try:
            if llm is None:
                await run_autopilot(eng, aggressive=aggressive, thorough=thorough, hint=hint)
            else:
                res = await Agent(eng, llm, aggressive, goal).run()
                ui.rule(f"agent stopped: {res.stopped}", "brain")
                if res.summary:
                    ui.console.print(f"[text]{res.summary}[/]")
                if eng.budget.cost:
                    ui.muted(f"tokens in/out: {eng.budget.tokens_in}/{eng.budget.tokens_out} · est. cost ${eng.budget.cost:.4f}")
        finally:
            if llm is not None:
                await llm.aclose()

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        ui.warn("forced exit")
    finally:
        _wrap_up(eng, started, quiet=hint)
        eng.close()
    if not hint:
        ui.muted(f"audit log: {eng.ws / 'audit.jsonl'}   verify: cyberred verify-log {eng.ws}")


# ------------------------------------------------------------------------------------------ demo

@app.command()
def demo(
    runner: Annotated[str, typer.Option(help="auto | docker | native")] = "native",
    workspace_dir: Annotated[Path, typer.Option()] = WS_DEFAULT,
) -> None:
    """See CyberRed work end-to-end against a built-in simulated vulnerable web app on 127.0.0.1."""
    from .demo import demo_server

    ui.banner(__version__, "demo · local simulated target, no network access needed")
    with demo_server() as port:
        cfg = Config.model_validate({
            "engagement": {"name": "demo", "mode": "lab"},
            "scope": {"include": [f"http://127.0.0.1:{port}/"]},
            "policy": {"approvals": {"T2": "auto"}},
        })
        eng = Engagement(cfg, new_workspace(workspace_dir, "demo"), runner, _make_approver(cfg, True))
        started = time.monotonic()
        ui.info(f"target: http://127.0.0.1:{port}/  (a throwaway server that only simulates weaknesses)", "target")

        async def go() -> None:
            await run_autopilot(eng, aggressive=True)

        try:
            asyncio.run(go())
        finally:
            _wrap_up(eng, started)
            eng.close()


# ------------------------------------------------------------------------------------------ post-run commands

def _open_ws(ws: Path) -> Store:
    if not (ws / "findings.db").exists():
        ui.err(f"{ws} does not look like a CyberRed workspace")
        raise typer.Exit(2)
    return Store(ws / "findings.db")


@app.command()
def status(workspace: Path) -> None:
    """Show the current state of an engagement workspace."""
    st = _open_ws(workspace)
    ui.info(f"{st.get_meta('name', workspace.name)}  ({st.get_meta('mode', '?')} mode)  started {st.get_meta('started', '?')}", "target")
    if st.hosts_with_services():
        ui.console.print(ui.hosts_table(st.hosts_with_services()))
    fs = st.findings()
    if fs:
        ui.console.print(ui.findings_table(fs))
    for f in st.flags():
        ui.console.print(f"{ui.em('flag')}[warn]{f['value']}[/]")
    ui.summary_panel(st.counts(), st.severity_counts(), st.counts()["flags"], st.counts()["runs"], 0)


@app.command()
def report(
    workspace: Path,
    format: Annotated[str, typer.Option("--format", "-f", help="md | json | writeup")] = "md",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Render a report from a workspace's findings database and audit log."""
    st = _open_ws(workspace)
    fn = {"md": render_markdown, "json": render_json, "writeup": render_writeup}.get(format)
    if not fn:
        ui.err("format must be md, json or writeup")
        raise typer.Exit(2)
    text = fn(workspace, st)
    if output:
        output.write_text(text)
        ui.ok(f"wrote {output}")
    else:
        typer.echo(text)


@app.command()
def stop(workspace: Path) -> None:
    """Kill switch: ask a running engagement to stop immediately."""
    (workspace / "STOP").write_text("stop\n")
    pid_file = workspace / "run.pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGTERM)
            ui.ok("sent stop signal to the running engagement")
            return
        except (ProcessLookupError, ValueError, PermissionError):
            pass
    ui.muted("no running process found; STOP marker written")


@app.command("verify-log")
def verify_log(workspace: Path) -> None:
    """Verify the audit log's hash chain (detects edited or deleted records)."""
    p = workspace / "audit.jsonl"
    if not p.exists():
        ui.err("no audit.jsonl in that workspace")
        raise typer.Exit(2)
    ok, n, bad = verify_audit_log(p)
    if ok:
        ui.ok(f"audit log intact: {n} records")
    else:
        ui.err(f"audit log TAMPERED at record {bad} (checked {n})")
        raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
