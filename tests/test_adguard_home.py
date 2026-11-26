"""AdGuard Home as a DNS source. A fake API, never a real resolver."""
import pytest
import requests
from floorbit.plugins.base import PluginError

T0 = 1_794_650_400


class Answer:
    def __init__(self, body, status=200):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


def iso(ts):
    from datetime import UTC, datetime
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


# Newest first, like AdGuard Home's log: 1200 lookups one second apart.
ADGUARD = [{"time": iso(T0 + 1200 - i), "question": {"name": f"cdn{i % 3}.steamcontent.com", "type": "A"},
            "client": f"198.51.100.{i % 50 + 1}",
            "reason": "FilteredBlackList" if i % 10 == 0 else "NotFilteredNotFound"}
           for i in range(1200)]


@pytest.fixture
def adguard(monkeypatch):
    calls = []

    def fake(self, method, url, **kw):
        assert url == "https://dns.example.com/control/querylog" and method == "GET"
        calls.append(dict(kw["params"]))
        if self.auth != ("floorbit", "example-password"):
            return Answer({}, 401)
        start = 0
        if "older_than" in kw["params"]:
            start = next(i for i, r in enumerate(ADGUARD) if r["time"] == kw["params"]["older_than"]) + 1
        page = ADGUARD[start:start + kw["params"]["limit"]]
        return Answer({"data": page, "oldest": page[-1]["time"] if page else ""})

    monkeypatch.setattr(requests.Session, "request", fake)
    return calls


SETTINGS = {"url": "https://dns.example.com", "username": "floorbit", "password": "example-password"}


def test_adguard_reads_back_to_the_cursor(make, adguard):
    got = make(**SETTINGS).dns_queries(T0 + 1200 - 700)
    assert len(got) == 701 and len(adguard) == 2                  # two pages of 500
    assert adguard[1]["older_than"] == ADGUARD[499]["time"]
    assert got[0] == {"ts": T0 + 1200 + 0.123456, "domain": "cdn0.steamcontent.com", "client": "198.51.100.1",
                      "blocked": True}
    assert sum(e["blocked"] for e in got) == 71
    assert min(e["ts"] for e in got) > T0 + 500


def test_adguard_explains_a_wrong_password(make, adguard):
    with pytest.raises(PluginError, match=r"^AdGuard Home refused the username or password\.$"):
        make(**{**SETTINGS, "password": "wrong"}).test()
    assert make(**SETTINGS).test()


def test_the_answers_come_along_for_naming_traffic():
    from conftest import load
    entry = load("plugin").entry
    row = {"time": iso(T0), "question": {"name": "cdn.example.com", "type": "A"}, "client": "198.51.100.1",
           "reason": "NotFilteredNotFound",
           "answer": [{"type": "CNAME", "value": "edge.example.net", "ttl": 60},
                      {"type": "A", "value": "203.0.113.7", "ttl": 55},
                      {"type": "AAAA", "value": "2001:db8::7", "ttl": 55}]}
    assert entry(row)["answers"] == [{"address": "203.0.113.7", "ttl": 55}, {"address": "2001:db8::7", "ttl": 55}]
    blocked = {**row, "reason": "FilteredBlackList", "answer": [{"type": "A", "value": "0.0.0.0", "ttl": 10}]}
    assert "answers" not in entry(blocked)
