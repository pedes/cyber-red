import base64
import json

from cyberred.knowledge.banners import parse_banner, parse_server_header
from cyberred.knowledge.hints import hints_for, vtuple
from cyberred.parsers import parse_ffuf, parse_nmap_xml, parse_nuclei, parse_searchsploit, parse_sqlmap

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.10.11.5" addrtype="ipv4"/>
<hostnames><hostname name="target.htb"/></hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
  <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
</ports>
<hostscript>
<script id="smb-security-mode" output="account_used: guest&#10;message_signing: disabled (dangerous, but default)"/>
<script id="smb-vuln-ms17-010" output="VULNERABLE:&#10;  State: VULNERABLE"/>
<script id="smb-os-discovery" output="&#10;  OS: Windows 7 Professional 7601 SP1"/>
</hostscript></host>
<host><status state="down"/><address addr="10.10.11.6" addrtype="ipv4"/></host></nmaprun>"""


def test_nmap_xml_hosts_services_and_script_findings():
    d = parse_nmap_xml(NMAP_XML)
    assert [h["address"] for h in d["hosts"]] == ["10.10.11.5"]  # down host skipped
    assert d["hosts"][0]["hostname"] == "target.htb" and "Windows 7" in d["hosts"][0]["os"]
    svc = {s["port"]: s for s in d["services"]}
    assert set(svc) == {21, 445, 8443}  # closed port skipped
    assert svc[21]["product"] == "vsftpd" and svc[8443]["name"] == "https"
    titles = {f["title"] for f in d["findings"]}
    assert {"Anonymous FTP login allowed", "SMB message signing disabled", "MS17-010 (EternalBlue) vulnerable"} <= titles
    ms17 = next(f for f in d["findings"] if f["title"].startswith("MS17"))
    assert ms17["severity"] == "critical" and ms17["cve"] == "CVE-2017-0143"


def test_nmap_garbage_is_safe():
    assert parse_nmap_xml("not xml")["hosts"] == []


def test_nuclei_jsonl():
    line = json.dumps({"template-id": "CVE-2021-41773", "matched-at": "http://t:8080/cgi-bin/x", "info": {
        "name": "Apache 2.4.49 traversal", "severity": "critical", "description": "d",
        "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 9.8}, "reference": ["https://a", "https://b", "https://c"]}})
    d = parse_nuclei("banner noise\n" + line + "\n{broken")
    f = d["findings"][0]
    assert f["severity"] == "critical" and f["cve"] == "CVE-2021-41773" and f["cvss"] == 9.8
    assert f["url"].startswith("http://t:8080") and f["status"] == "confirmed" and f["remediation"].count("https") == 2


def test_ffuf_json_lines():
    rec = {"url": "http://t/admin", "status": 301, "length": 10, "input": {"FUZZ": base64.b64encode(b"admin").decode()}}
    d = parse_ffuf("\n".join([json.dumps(rec), json.dumps(rec), "garbage"]))
    assert len(d["endpoints"]) == 1 and d["endpoints"][0]["word"] == "admin"


def test_sqlmap_detection_and_negative():
    out = "Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\nback-end DBMS: MySQL >= 5.0"
    f = parse_sqlmap(out, "http://t/item?id=1")["findings"][0]
    assert f["severity"] == "critical" and "MySQL" in f["description"] and "boolean-based blind" in f["evidence"]
    assert parse_sqlmap("all tested parameters do not appear to be injectable", "http://t")["findings"] == []


def test_searchsploit():
    hits = parse_searchsploit(json.dumps({"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 - Backdoor", "EDB-ID": "17491", "Type": "remote", "Path": "x"}]}))
    assert hits[0]["edb"] == "17491" and parse_searchsploit("nope") == []


def test_version_tuples_and_hints():
    assert vtuple("7.2p2") == (7, 2, 2)
    assert [h.cve for h in hints_for("vsftpd", "2.3.4")] == ["CVE-2011-2523"]
    assert any(h.cve == "CVE-2018-15473" for h in hints_for("OpenSSH", "7.2p2"))
    assert not hints_for("OpenSSH", "9.6p1")
    assert any(h.cve == "CVE-2021-41773" for h in hints_for("Apache httpd", "2.4.49"))
    assert not any(h.cve for h in hints_for("Apache httpd", "2.4.58"))
    assert any(h.cve == "CVE-2017-7494" for h in hints_for("Samba smbd", "4.5.9"))
    assert not any(h.cve == "CVE-2017-7494" for h in hints_for("Samba smbd", "4.5.10"))
    assert any(h.cve == "CVE-2019-10149" for h in hints_for("Exim smtpd", "4.89"))
    assert hints_for(None, "1.0") == [] and hints_for("x", None) == []
    assert all(h.status == "candidate" for h in hints_for("vsftpd", "2.3.4"))  # banner-only → never 'confirmed'


def test_banner_parsing():
    assert parse_banner(22, "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8") == ("ssh", "OpenSSH", "7.2p2")
    assert parse_banner(21, "220 (vsFTPd 2.3.4)") == ("ftp", "vsftpd", "2.3.4")
    assert parse_banner(21, "220 ProFTPD 1.3.5 Server ready") == ("ftp", "ProFTPD", "1.3.5")
    assert parse_banner(25, "220 mail ESMTP Exim 4.89 Mon") == ("smtp", "Exim", "4.89")
    assert parse_banner(80, "HTTP/1.0 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n") == ("http", "Apache httpd", "2.4.49")
    assert parse_banner(3306, "\x0a5.7.33-0ubuntu0.18.04.1\x00") == ("mysql", "MySQL", "5.7.33-0ubuntu0.18.04.1")
    assert parse_banner(9999, "") == ("unknown", None, None)
    assert parse_server_header("nginx/1.18.0 (Ubuntu)") == ("nginx", "1.18.0")
