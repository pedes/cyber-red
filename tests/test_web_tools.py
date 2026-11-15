
from conftest import approve_all, run_async
from cyberred.core import run_autopilot
from cyberred.demo import demo_server


def titles(eng):
    return {f["title"] for f in eng.store.findings()}


def test_http_probe_finds_hygiene_issues_and_records_service(make_eng):
    with demo_server() as port:
        eng = make_eng(include=[f"http://127.0.0.1:{port}/"])
        r = run_async(eng.executor.execute("http_probe", {"url": f"http://127.0.0.1:{port}/"}))
        assert r.ok
    t = titles(eng)
    assert {"Missing HTTP security headers", "Cookies missing security attributes", "Login form served over cleartext HTTP",
            "CORS reflects arbitrary origin with credentials", "Potentially dangerous HTTP methods advertised",
            "Web server version disclosed"} <= t
    assert "Apache httpd 2.4.49 path traversal / RCE" in t  # version hint derived from the Server header
    assert eng.store.services()[0]["product"] == "Apache httpd"


def test_common_files_validates_content_and_masks_secrets(make_eng):
    with demo_server() as port:
        eng = make_eng(include=[f"http://127.0.0.1:{port}/"])
        run_async(eng.executor.execute("web_common_files", {"url": f"http://127.0.0.1:{port}/"}))
    t = titles(eng)
    assert {"Exposed .git repository", "Exposed .env file"} <= t
    env = next(f for f in eng.store.findings() if f["title"] == "Exposed .env file")
    assert "hunter2" not in env["evidence"] and "DB_PASSWORD=***" in env["evidence"]
    assert any(e["url"].endswith("/admin-panel/") for e in eng.store.endpoints())  # robots.txt Disallow entries become endpoints
    assert "phpinfo() page exposed" not in t  # no false positives for paths that 404


def test_crawl_discovers_params_and_forms(make_eng):
    with demo_server() as port:
        eng = make_eng(include=[f"http://127.0.0.1:{port}/"])
        run_async(eng.executor.execute("web_crawl", {"url": f"http://127.0.0.1:{port}/"}))
    eps = {e["url"]: e for e in eng.store.endpoints()}
    assert any(u.endswith("/search?q=hello") and e["params"] == "q" for u, e in eps.items())
    assert any(e["method"] == "POST" and "username" in (e["params"] or "") for e in eps.values())
    assert "Sensitive-looking HTML comment" in titles(eng)


def test_param_probe_flags_reflection_and_sql_errors(make_eng):
    with demo_server() as port:
        eng = make_eng(approver=approve_all, include=[f"http://127.0.0.1:{port}/"])
        run_async(eng.executor.execute("web_param_probe", {"url": f"http://127.0.0.1:{port}/item?id=1"}))
        run_async(eng.executor.execute("web_param_probe", {"url": f"http://127.0.0.1:{port}/search?q=a"}))
    fs = {f["title"]: f for f in eng.store.findings()}
    assert fs["Possible SQL injection (database error on quote)"]["status"] == "candidate"
    assert fs["Reflected input is not encoded (potential XSS)"]["severity"] == "medium"


def test_redirect_to_out_of_scope_host_is_not_followed(make_eng):
    with demo_server() as port:
        eng = make_eng(include=[f"http://127.0.0.1:{port}/"])
        r = run_async(eng.executor.execute("http_probe", {"url": f"http://127.0.0.1:{port}/redirect-out"}))
    assert not r.ok and "out of scope" in r.text and "203.0.113.9" in r.text


def test_dns_rebinding_peer_mismatch_is_detected(make_eng, monkeypatch):
    """Scope pinned to an address the server is NOT at: the connected peer differs from the pinned resolution."""

    with demo_server() as port:
        eng = make_eng(include=["10.255.255.1/32", "127.0.0.1/32"], scope={"include": ["10.255.255.1/32", "127.0.0.1/32"], "hosts": {"app.test": "10.255.255.1"}})
        # name is pinned to 10.255.255.1 in scope, but we make the OS connect to 127.0.0.1 instead
        import httpx

        orig = httpx.AsyncClient.stream

        def redirected(self, method, url, **kw):
            return orig(self, method, str(url).replace("app.test", "127.0.0.1"), **kw)

        monkeypatch.setattr(httpx.AsyncClient, "stream", redirected)
        r = run_async(eng.executor.execute("http_probe", {"url": f"http://app.test:{port}/"}))
    assert not r.ok and "rebinding" in r.text.lower()


def test_tcp_port_scan_banner_and_service_fingerprint(make_eng):
    with demo_server() as port:
        eng = make_eng(include=["127.0.0.1"])
        r = run_async(eng.executor.execute("tcp_port_scan", {"targets": ["127.0.0.1"], "ports": f"{port},1"}))
        assert r.ok
    svc = eng.store.services()
    assert [s["port"] for s in svc] == [port] and svc[0]["product"] == "Apache httpd"
    assert {"Apache httpd 2.4.49 path traversal / RCE"} <= titles(eng)


def test_autopilot_end_to_end_without_llm_or_binaries(make_eng):
    with demo_server() as port:
        eng = make_eng(approver=approve_all, include=[f"http://127.0.0.1:{port}/"])
        run_async(run_autopilot(eng, aggressive=True))
    runs = [r["tool"] for r in eng.store.runs()]
    assert runs.count("http_probe") == 1 and runs.count("web_common_files") == 1  # URL seed + discovered service are deduped
    assert {"web_crawl", "web_param_probe"} <= set(runs)
    assert len(eng.store.findings()) >= 12
    sev = eng.store.severity_counts()
    assert sev["critical"] == 1 and sev["high"] >= 3


def test_autopilot_without_aggressive_never_touches_t2(make_eng):
    with demo_server() as port:
        eng = make_eng(approver=approve_all, include=[f"http://127.0.0.1:{port}/"])
        run_async(run_autopilot(eng))
    assert "web_param_probe" not in [r["tool"] for r in eng.store.runs()]
