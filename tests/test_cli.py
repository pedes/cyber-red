import json

from typer.testing import CliRunner

from cyberred.cli import app

runner = CliRunner()


def test_init_writes_valid_scope_and_refuses_overwrite(tmp_path):
    p = tmp_path / "scope.yaml"
    r = runner.invoke(app, ["init", "-t", "10.10.11.0/24", "-t", "target.htb", "--mode", "ctf", "--name", "box1", "-o", str(p)])
    assert r.exit_code == 0 and p.exists()
    assert runner.invoke(app, ["init", "-t", "1.2.3.4", "-o", str(p)]).exit_code == 1
    r = runner.invoke(app, ["scope-check", str(p), "10.10.11.7", "10.10.12.7", "8.8.8.8"])
    assert r.stdout.count("→  in scope") == 1 and r.stdout.count("BLOCKED") == 2


def test_engagement_mode_scope_needs_authorization(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("engagement: {mode: engagement}\nscope: {include: [10.0.0.1]}\n")
    r = runner.invoke(app, ["run", str(p), "--autopilot"])
    assert r.exit_code == 2 and "authorization" in r.stdout


def test_missing_scope_file_and_unknown_keys(tmp_path):
    assert runner.invoke(app, ["run", str(tmp_path / "nope.yaml")]).exit_code == 2
    p = tmp_path / "s.yaml"
    p.write_text("scope: {include: [10.0.0.1]}\nsurprise: 1\n")
    r = runner.invoke(app, ["run", str(p), "--autopilot"])
    assert r.exit_code == 2 and "surprise" in r.stdout


def test_demo_then_status_report_and_verify_log(tmp_path):
    r = runner.invoke(app, ["--no-emoji", "demo", "--workspace-dir", str(tmp_path)])
    assert r.exit_code == 0, r.stdout
    assert "engagement summary" in r.stdout and "report:" in r.stdout
    ws = next(tmp_path.iterdir())
    assert (ws / "report.md").exists() and (ws / "audit.jsonl").exists()
    assert runner.invoke(app, ["verify-log", str(ws)]).exit_code == 0
    st = runner.invoke(app, ["status", str(ws)])
    assert st.exit_code == 0 and "Exposed .git repository" in st.stdout
    data = json.loads(runner.invoke(app, ["report", str(ws), "-f", "json"]).stdout)
    assert data["severity_counts"]["critical"] == 1 and data["counts"]["findings"] >= 12
    md = runner.invoke(app, ["report", str(ws)]).stdout
    assert "## Findings" in md and "hunter2" not in md
    assert "Step 1" in runner.invoke(app, ["report", str(ws), "-f", "writeup"]).stdout
    # tamper → verify-log fails
    log = ws / "audit.jsonl"
    log.write_text(log.read_text().replace('"lab"', '"ctf"', 1))
    assert runner.invoke(app, ["verify-log", str(ws)]).exit_code == 1


def test_hint_mode_lists_suggestions_and_runs_nothing(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("engagement: {mode: lab}\nscope: {include: [127.0.0.1]}\n")
    r = runner.invoke(app, ["run", str(p), "--autopilot", "--hint", "--workspace-dir", str(tmp_path / "w"), "--runner", "native"])
    assert r.exit_code == 0 and "suggested next actions" in r.stdout and "tcp_port_scan" in r.stdout
    ws = next((tmp_path / "w").iterdir())
    assert not list((ws / "runs").glob("*")) if (ws / "runs").exists() else True


def test_tools_and_doctor_render():
    assert runner.invoke(app, ["tools"]).exit_code == 0
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0 and "Python" in r.stdout
