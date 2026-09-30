from nextdns_sentinel import domain_matches, event_domain, event_reason, event_status, event_client_ip, matched_domain

def test_domain_matches_exact_and_parent():
    denylist = {"example.com"}
    assert domain_matches("example.com", denylist)
    assert domain_matches("sub.example.com", denylist)
    assert not domain_matches("example.net", denylist)

def test_domain_matches_wildcard():
    assert domain_matches("sub.example.com", {"*.example.com"})
    assert not domain_matches("example.com", {"*.example.com"})

def test_event_fields():
    log = {
        "domain": "Example.COM.",
        "matched_name": "example.com",
        "status": "blocked",
        "reasons": ["denylist", "security"],
        "client": {"ip": "192.0.2.10"},
    }
    assert event_domain(log) == "example.com"
    assert matched_domain(log) == "example.com"
    assert event_status(log) == "blocked"
    assert event_reason(log) == "denylist, security"
    assert event_client_ip(log) == "192.0.2.10"
