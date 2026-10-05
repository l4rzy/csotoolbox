from infrastructure.utils import extract_host


def test_hostport_ip():
    assert extract_host("103.226.250.88:1632") == "103.226.250.88"
    assert extract_host("192.168.1.1:8080") == "192.168.1.1"


def test_hostport_domain():
    assert extract_host("example.com:443") == "example.com"
    assert extract_host("sub.domain.com:3000") == "sub.domain.com"


def test_urls():
    assert extract_host("https://example.com:443/path") == "example.com"
    assert extract_host("http://example.com") == "example.com"
    assert extract_host("HTTP://EXAMPLE.COM") == "example.com"
    assert extract_host("ftp://files.example.com:21/dir") == "files.example.com"
    assert extract_host("https://user:pass@example.com:8080/path") == "example.com"


def test_emails():
    assert extract_host("user@host.com") == "host.com"
    assert extract_host("user@host.com:993") == "host.com"
    assert extract_host("user@1.2.3.4:8080") == "1.2.3.4"


def test_bare_hostname():
    assert extract_host("example.com") == "example.com"


def test_bare_ip():
    assert extract_host("1.2.3.4") == "1.2.3.4"
    assert extract_host("::1") == "::1"
    assert extract_host("[::1]:80") == "::1"


def test_edge_cases():
    assert extract_host("") == ""
    assert extract_host("   ") == ""
    assert extract_host("   example.com:443   ") == "example.com"
    assert extract_host("a1.2.3.5:4331/") == "a1.2.3.5"
