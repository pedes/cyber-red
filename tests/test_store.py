import json

from cyberred.core.ingest import ingest
from cyberred.models import Finding
from cyberred.store import AuditLog, Store, verify_audit_log


def test_findings_dedupe_and_candidate_upgrades_to_confirmed(tmp_path):
    s = Store(tmp_path / "f.db")
    a = Finding("Open redirect", "low", host="h", url="http://h/x", status="candidate")
    fid, created = s.add_finding(a)
    assert created
    fid2, created2 = s.add_finding(Finding("open redirect", "low", host="h", url="http://h/x", status="confirmed", evidence="proof"))
    assert fid2 == fid and not created2
    row = s.findings()[0]
    assert row["status"] == "confirmed" and row["evidence"] == "proof"
    assert s.add_finding(Finding("Open redirect", "low", host="h", url="http://h/y"))[1]  # different asset → new


def test_findings_sorted_by_severity(tmp_path):
    s = Store(tmp_path / "f.db")
    for sev in ("low", "critical", "info", "high"):
        s.add_finding(Finding(f"t-{sev}", sev, host="h"))
    assert [f["severity"] for f in s.findings()] == ["critical", "high", "low", "info"]
    assert s.severity_counts()["high"] == 1


def test_service_upsert_enriches_and_reports_gained_info(tmp_path):
    s = Store(tmp_path / "f.db")
    _, new = s.upsert_service("10.0.0.5", 80, name="http")
    assert new
    _, gained = s.upsert_service("10.0.0.5", 80, product="nginx", version="1.2")
    assert gained
    _, again = s.upsert_service("10.0.0.5", 80, product="nginx", version="1.2")
    assert not again
    assert s.services()[0]["product"] == "nginx"


def test_runs_cache_lookup_only_for_successful_runs(tmp_path):
    s = Store(tmp_path / "f.db")
    rid = s.start_run("t", {"a": 1})
    s.finish_run(rid, "error", 1, "bad", "", 0.1)
    assert s.find_run("t", {"a": 1}) is None
    rid2 = s.start_run("t", {"a": 1})
    s.finish_run(rid2, "ok", 0, "good", "", 0.1)
    assert s.find_run("t", {"a": 1})["id"] == rid2
    assert s.find_run("t", {"a": 2}) is None


def test_ingest_derives_hint_and_exposure_findings_once(tmp_path):
    s = Store(tmp_path / "f.db")
    data = {"services": [{"address": "10.0.0.5", "port": 21, "name": "ftp", "product": "vsftpd", "version": "2.3.4"},
                         {"address": "10.0.0.5", "port": 23, "name": "telnet"}]}
    r = ingest(s, data, "tcp_port_scan")
    titles = {f.title for f in r.new_findings}
    assert {"vsFTPd 2.3.4 backdoor", "Telnet service exposed", "FTP service exposed (cleartext protocol)"} <= titles
    assert not ingest(s, data, "tcp_port_scan").new_findings  # idempotent


def test_audit_log_chain_continues_across_reopen_and_redacts_secrets(tmp_path):
    p = tmp_path / "a.jsonl"
    a = AuditLog(p)
    a.log("x", api_key="sk-live-123", nested={"password": "hunter2", "ok": 1})
    a.close()
    b = AuditLog(p)
    b.log("y")
    b.close()
    ok, n, _ = verify_audit_log(p)
    assert ok and n == 2
    text = p.read_text()
    assert "sk-live-123" not in text and "hunter2" not in text and '"ok": 1' in text
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[1], lines[0]]) + "\n")  # reordered
    assert not verify_audit_log(p)[0]
    p.write_text(lines[1] + "\n")  # first record deleted
    assert not verify_audit_log(p)[0]
    assert json.loads(lines[0])["seq"] == 1
