from conftest import run_async
from cyberred.core import suggest

NMAP_OUT = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.10.11.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
</ports></host></nmaprun>"""


def tools_of(eng, **kw):
    return [s.tool for s in suggest(eng, **kw)]


def test_uses_python_scanner_without_nmap_and_nmap_when_present(make_eng):
    assert tools_of(make_eng(include=["10.10.11.5"])) == ["tcp_port_scan"]
    eng = make_eng(include=["10.10.11.5"], binaries={"nmap"})
    assert tools_of(eng) == ["nmap_scan"]
    assert suggest(eng)[0].args == {"targets": ["10.10.11.5"], "scan": "quick", "skip_ping": True}  # defaults filled, like the executor


def test_cidr_seed_starts_with_discovery_and_thorough_adds_full_sweep(make_eng):
    eng = make_eng(include=["10.10.11.0/28"], binaries={"nmap"})
    assert suggest(eng)[0].args["scan"] == "discovery"
    eng2 = make_eng(include=["10.10.11.5"], binaries={"nmap"})
    assert any(s.args.get("scan") == "full" for s in suggest(eng2, thorough=True))
    assert not any(s.args.get("scan") == "full" for s in suggest(eng2))


def test_hostname_seed_resolves_first(make_eng):
    eng = make_eng(include=["box.htb", "10.10.11.0/24"], scope={"include": ["box.htb", "10.10.11.0/24"], "hosts": {"box.htb": "10.10.11.5"}})
    assert suggest(eng)[0].tool == "dns_lookup"


def test_services_drive_protocol_specific_followups(make_eng):
    eng = make_eng(include=["10.10.11.5"], binaries={"nmap", "nuclei", "ffuf", "searchsploit"}, outputs={"nmap": NMAP_OUT})
    run_async(eng.executor.execute("nmap_scan", {"targets": ["10.10.11.5"], "scan": "quick"}))
    s = suggest(eng)
    by_tool = {}
    for x in s:
        by_tool.setdefault(x.tool, []).append(x)
    assert by_tool["ftp_anon_check"][0].args == {"target": "10.10.11.5", "port": 21}
    assert "smb-vuln-ms17-010" in by_tool["nmap_scripts"][0].args["scripts"]
    assert by_tool["exposed_service_check"][0].args["service"] == "redis"
    assert by_tool["http_probe"][0].args["url"] == "https://10.10.11.5"
    assert {"tls_inspect", "web_common_files", "web_crawl", "ffuf_discover", "nuclei_scan"} <= set(by_tool)
    assert any("vsftpd 2.3.4" in x.args["query"] for x in by_tool["searchsploit_lookup"])
    # ordering: cheap recon/enumeration first, template scanning later
    order = [x.tool for x in s]
    assert order.index("http_probe") < order.index("nuclei_scan")


def test_completed_work_is_not_suggested_again(make_eng):
    eng = make_eng(include=["10.10.11.5"], binaries={"nmap", "searchsploit"}, outputs={"nmap": NMAP_OUT, "searchsploit": '{"RESULTS_EXPLOIT": []}'})
    run_async(eng.executor.execute("nmap_scan", {"targets": ["10.10.11.5"], "scan": "quick"}))
    first = suggest(eng)
    assert any(s.tool == "ftp_anon_check" for s in first)
    ss = next(s for s in first if s.tool == "searchsploit_lookup")
    run_async(eng.executor.execute(ss.tool, ss.args))
    assert all(s.key != ss.key for s in suggest(eng))  # succeeded → done
    assert all(s.tool != "nmap_scan" for s in suggest(eng))


def test_failed_and_declined_steps_are_not_resuggested(make_eng):
    eng = make_eng(include=["10.10.11.5"], binaries={"nmap"}, outputs={"nmap": NMAP_OUT})
    run_async(eng.executor.execute("nmap_scan", {"targets": ["10.10.11.5"], "scan": "quick"}))
    ftp = next(s for s in suggest(eng) if s.tool == "ftp_anon_check")
    run_async(eng.executor.execute(ftp.tool, ftp.args))  # nothing listens on 10.10.11.5 here, so this errors
    assert eng.store.runs()[-1]["status"] == "error"
    assert all(s.key != ftp.key for s in suggest(eng))  # a failed attempt is not nagged again
    eng.executor.declined.add(next(s for s in suggest(eng) if s.tool == "exposed_service_check").key)
    assert not any(s.tool == "exposed_service_check" for s in suggest(eng))


def test_t2_only_with_aggressive_and_tier_policy(make_eng):
    eng = make_eng(include=["10.10.11.5"], binaries={"nmap", "sqlmap"})
    eng.store.add_endpoint("http://10.10.11.5/item?id=1", 200, params=["id"])
    assert "web_param_probe" not in tools_of(eng)
    assert "web_param_probe" in tools_of(eng, aggressive=True)
    eng2 = make_eng(include=["10.10.11.5"], policy={"allowed_tiers": ["T0", "T1"]})
    eng2.store.add_endpoint("http://10.10.11.5/item?id=1", 200, params=["id"])
    assert "web_param_probe" not in tools_of(eng2, aggressive=True)


def test_nuclei_tags_follow_detected_tech(make_eng):
    eng = make_eng(include=["http://10.10.11.5/"], binaries={"nuclei"})
    eng.store.add_endpoint("http://10.10.11.5", 200, tech=["wordpress", "apache", "php"])
    n = next(s for s in suggest(eng) if s.tool == "nuclei_scan")
    assert n.args["tags"].startswith("apache,php,wordpress") and "wordpress" in n.reason


def test_tool_registry_is_safe_by_construction():
    from cyberred.config import Tier
    from cyberred.tools import build_registry

    reg = build_registry()
    assert all(t.tier != Tier.T3 for t in reg.all())
    # nothing exposes arbitrary command execution or sqlmap's dangerous switches
    names = {t.name for t in reg.all()}
    assert not {"raw_command", "shell", "exec", "run_command"} & names
    sqlmap = reg.get("sqlmap_test")
    assert set(sqlmap.params) == {"url", "param", "data"}
    schemas = [t.json_schema() for t in reg.all()]
    assert all(s["additionalProperties"] is False for s in schemas)
