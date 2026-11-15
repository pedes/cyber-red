import pytest

from cyberred.config import ScopeCfg
from cyberred.policy.scope import ScopeEngine, ScopeViolation

DNS = {
    "target.htb": ["10.10.11.5"],
    "www.example.com": ["93.184.216.34"],
    "api.example.com": ["10.0.0.9"],
    "evil.example.org": ["8.8.8.8"],
    "rebind.example.com": ["127.0.0.1"],
    "mixed.example.com": ["10.10.11.5", "8.8.8.8"],
    "admin.target.htb": ["10.10.11.77"],
}


def resolver(host):
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


def engine(include, exclude=(), hosts=None):
    return ScopeEngine(ScopeCfg(include=list(include), exclude=list(exclude), hosts=hosts or {}), resolver=resolver)


def test_ip_and_cidr_membership():
    s = engine(["10.10.11.0/24"], ["10.10.11.1"])
    assert s.check("10.10.11.5").addresses == ("10.10.11.5",)
    for bad in ("10.10.12.5", "10.10.11.1", "8.8.8.8"):
        with pytest.raises(ScopeViolation):
            s.check(bad)


def test_exclusion_always_wins_even_for_hostnames():
    s = engine(["10.10.11.0/24", "target.htb"], ["10.10.11.5"])
    with pytest.raises(ScopeViolation, match="excluded"):
        s.check("target.htb")


def test_cidr_target_expands_minus_exclusions():
    s = engine(["10.10.11.0/29"], ["10.10.11.3"])
    r = s.check("10.10.11.0/29")
    assert "10.10.11.3" not in r.addresses
    assert "10.10.11.1" in r.addresses and r.kind == "cidr"


def test_cidr_target_must_be_fully_inside_scope():
    s = engine(["10.10.11.0/24"])
    with pytest.raises(ScopeViolation):
        s.check("10.10.0.0/16")


def test_huge_cidr_rejected():
    s = engine(["10.0.0.0/8"])
    with pytest.raises(ScopeViolation, match="too large"):
        s.check("10.0.0.0/8")


def test_hostname_resolution_must_land_in_scope():
    s = engine(["10.10.11.0/24"])
    assert s.check("target.htb").addresses == ("10.10.11.5",)
    with pytest.raises(ScopeViolation):
        s.check("evil.example.org")


def test_mixed_resolution_is_rejected():
    s = engine(["10.10.11.0/24"])
    with pytest.raises(ScopeViolation):
        s.check("mixed.example.com")


def test_wildcard_name_include_and_special_address_guard():
    s = engine(["*.example.com"])
    assert s.check("api.example.com").addresses == ("10.0.0.9",)
    # an in-scope *name* that resolves to loopback must not be reachable (SSRF-style pivot)
    with pytest.raises(ScopeViolation, match="special-use"):
        s.check("rebind.example.com")


def test_unresolvable_host():
    s = engine(["*.example.com"])
    with pytest.raises(ScopeViolation, match="cannot resolve"):
        s.check("nope.example.com")


@pytest.mark.parametrize("raw", [
    "http://10.10.11.5@evil.example.org/", "http://evil.example.org\\@10.10.11.5/", "10.10.11.5 evil",
    "2130706433", "0x7f.1", "-oN /tmp/x", "", "file:///etc/passwd", "ftp://10.10.11.5/", "10.10.11.5\n8.8.8.8",
])
def test_malformed_and_tricky_targets_rejected(raw):
    s = engine(["10.10.11.0/24", "127.0.0.1"])
    with pytest.raises(ScopeViolation):
        s.check(raw)


def test_url_include_scopes_host_port_and_path():
    s = engine(["http://target.htb:8080/app/"])
    assert s.check("http://target.htb:8080/app/login?x=1").url == "http://target.htb:8080/app/login?x=1"
    for bad in ("http://target.htb:8080/other", "http://target.htb:9090/app/", "https://target.htb:8080/app/",
                "http://target.htb:8080/app/../admin"):
        with pytest.raises(ScopeViolation):
            s.check(bad)


def test_url_path_encoded_traversal_rejected():
    s = engine(["http://target.htb/app"])
    with pytest.raises(ScopeViolation):
        s.check("http://target.htb/app/%2e%2e/admin")
    assert s.check("http://target.htb/app/x").kind == "url"


def test_url_in_network_scope_and_default_ports():
    s = engine(["10.10.11.0/24"])
    r = s.check("https://10.10.11.5/login")
    assert r.port == 443 and r.scheme == "https"
    r = s.check("10.10.11.5:8080")
    assert r.port == 8080 and r.kind == "ip"


def test_static_host_mapping_pins_resolution():
    s = engine(["10.10.11.0/24"], hosts={"box.htb": "10.10.11.9"})
    assert s.check("box.htb").addresses == ("10.10.11.9",)


def test_resolution_is_cached_against_rebinding():
    calls = {"n": 0}

    def flipping(host):
        calls["n"] += 1
        return ["10.0.0.9"] if calls["n"] == 1 else ["8.8.8.8"]

    s = ScopeEngine(ScopeCfg(include=["10.0.0.0/24"]), resolver=flipping)
    assert s.check("x.example.com").addresses == ("10.0.0.9",)
    assert s.check("x.example.com").addresses == ("10.0.0.9",)  # still the first answer
    assert calls["n"] == 1


def test_excluded_hostname_blocks_its_addresses():
    s = engine(["10.10.11.0/24"], ["admin.target.htb"])
    with pytest.raises(ScopeViolation):
        s.check("10.10.11.77")
    assert s.check("10.10.11.78").addresses == ("10.10.11.78",)


def test_ipv6():
    s = engine(["fd00::/64"])
    assert s.check("fd00::5").addresses == ("fd00::5",)
    with pytest.raises(ScopeViolation):
        s.check("fd01::5")
