"""RDAP (WHOIS) lookups. Records are synthetic but shaped like each registry's real answers."""
import unittest
from unittest import mock

import api
import rdap


def card(fn, kind, email=None, tel=None):
    items = [["version", {}, "text", "4.0"], ["fn", {}, "text", fn], ["kind", {}, "text", kind]]
    if email:
        items.append(["email", {}, "text", email])
    if tel:
        items.append(["tel", {"type": "voice"}, "text", tel])
    return ["vcard", items]


# ARIN nests the abuse contact inside the registrant organisation.
ARIN = {
    "objectClassName": "ip network", "handle": "NET-8-0-0-0-1", "name": "EXAMPLE-NET",
    "startAddress": "8.0.0.0", "endAddress": "8.0.255.255", "type": "ALLOCATION",
    "cidr0_cidrs": [{"v4prefix": "8.0.0.0", "length": 16}],
    "events": [{"eventAction": "registration", "eventDate": "2016-11-29T07:53:50-05:00"},
               {"eventAction": "last changed", "eventDate": "2020-01-02T00:00:00-05:00"}],
    "links": [{"rel": "self", "href": "https://rdap.arin.net/registry/ip/8.0.0.0"}],
    "entities": [{
        "handle": "EXCO", "roles": ["registrant"], "vcardArray": card("Example Cable, LLC", "org"),
        "entities": [
            {"handle": "ABUSE1-ARIN", "roles": ["abuse"],
             "vcardArray": card("Network Abuse", "group", "abuse@example.net", "+1-555-0100")},
            {"handle": "NOC1-ARIN", "roles": ["technical", "administrative"],
             "vcardArray": card("Example NOC", "group", "noc@example.net")},
        ]}],
}

# RIPE lists the abuse-c at the top level, often twice, plus phone-only staff.
RIPE = {
    "objectClassName": "ip network", "handle": "92.208.0.0 - 92.219.255.255",
    "name": "DE-EXAMPLE", "country": "DE", "startAddress": "92.208.0.0",
    "endAddress": "92.219.255.255",
    "entities": [
        {"handle": "AB1-RIPE", "roles": ["administrative", "technical"],
         "vcardArray": card("Example Backbone", "group", "abuse.de@example.com")},
        {"handle": "EX-MNT", "roles": ["registrant"], "vcardArray": card("EX-MNT", "individual")},
        {"handle": "ORG-EX1-RIPE", "roles": ["registrant"], "vcardArray": card("Example GmbH", "org")},
        {"handle": "AB1-RIPE", "roles": ["abuse"],
         "vcardArray": card("Example Backbone", "group", "abuse.de@example.com"),
         "entities": [{"handle": "JD1-RIPE", "roles": ["administrative"],
                       "vcardArray": card("Jane Doe", "individual", tel="+49 0000")}]},
    ],
}

# Some AFRINIC records have no abuse role at all.
AFRINIC = {
    "objectClassName": "ip network", "startAddress": "41.203.16.0", "endAddress": "41.203.19.255",
    "entities": [{"handle": "HIA1-AFRINIC", "roles": ["administrative", "technical"],
                  "vcardArray": card("Hosting IP Admin", "group", "ipadmin@example.org")}],
}

# APNIC sometimes only names the abuse mailbox in remarks.
APNIC = {
    "objectClassName": "ip network", "name": "EXAMPLE-AP", "country": "NZ",
    "remarks": [{"title": "description", "description": ["Example Telecom"]},
                {"title": "remarks", "description": ["Send abuse reports to abuse@example.co.nz"]}],
    "entities": [{"handle": "IA1-AP", "roles": ["technical"],
                  "vcardArray": card("IP Administrator", "individual", "ip@example.co.nz")}],
}


class SummaryTest(unittest.TestCase):
    def test_arin_nested_abuse(self):
        s = rdap.summarize(ARIN, "https://rdap.arin.net/registry/ip/8.0.0.1")
        self.assertEqual(s["registry"], "ARIN")
        self.assertEqual(s["org"], "Example Cable, LLC")
        self.assertEqual((s["abuse"], s["abuse_source"]), (["abuse@example.net"], "abuse"))
        self.assertEqual(s["range"], "8.0.0.0 – 8.0.255.255")
        self.assertEqual(s["cidrs"], ["8.0.0.0/16"])
        self.assertEqual(s["link"], "https://rdap.arin.net/registry/ip/8.0.0.0")
        self.assertEqual(s["registered"], "2016-11-29T07:53:50-05:00")
        abuse = [c for c in s["contacts"] if c["handle"] == "ABUSE1-ARIN"][0]
        self.assertEqual(abuse["phones"], ["+1-555-0100"])

    def test_ripe_merges_repeated_contact_and_skips_phone_only_people(self):
        s = rdap.summarize(RIPE, "https://rdap.db.ripe.net/ip/92.218.0.1")
        self.assertEqual((s["registry"], s["org"]), ("RIPE NCC", "Example GmbH"))
        self.assertEqual(s["abuse"], ["abuse.de@example.com"])
        handles = [c["handle"] for c in s["contacts"]]
        self.assertEqual(handles.count("AB1-RIPE"), 1)
        self.assertNotIn("JD1-RIPE", handles)
        self.assertEqual(set(s["contacts"][0]["roles"]), {"administrative", "technical", "abuse"})

    def test_fallbacks(self):
        s = rdap.summarize(AFRINIC, "https://rdap.afrinic.net/rdap/ip/41.203.18.1")
        self.assertEqual((s["abuse"], s["abuse_source"]), (["ipadmin@example.org"], "other"))
        s = rdap.summarize(APNIC, "https://krnic.rdap.apnic.net/ip/1.1.1.1")
        self.assertEqual(s["registry"], "KRNIC")
        self.assertEqual(s["org"], "Example Telecom")
        self.assertEqual((s["abuse"], s["abuse_source"]), (["abuse@example.co.nz"], "remarks"))

    def test_ignores_junk(self):
        s = rdap.summarize({"entities": [{"vcardArray": ["vcard", [["email", {}, "text",
                                                                    "not an email"]]],
                                          "roles": ["abuse"]}, "x", None],
                            "links": [{"rel": "self", "href": "javascript:alert(1)"}]})
        self.assertEqual(s["abuse"], [])
        self.assertIsNone(s["link"])


class ServerTest(unittest.TestCase):
    def test_bootstrap(self):
        self.assertEqual(rdap.server_for("92.218.214.194"), "https://rdap.db.ripe.net/")
        self.assertEqual(rdap.server_for("50.252.211.97"), "https://rdap.arin.net/registry/")
        self.assertEqual(rdap.server_for("122.58.188.143"), "https://rdap.apnic.net/")
        self.assertEqual(rdap.server_for("200.160.2.3"), "https://rdap.lacnic.net/rdap/")
        self.assertEqual(rdap.server_for("41.203.18.1"), "https://rdap.afrinic.net/rdap/")
        self.assertEqual(rdap.server_for("2a00:1450::1"), "https://rdap.db.ripe.net/")
        self.assertEqual(rdap.server_for("4000::1"), rdap.FALLBACK)

    def test_redirects_must_stay_https(self):
        h = rdap._HttpsOnly()
        with self.assertRaises(rdap.LookupFailed):
            h.redirect_request(None, None, 302, "Found", {}, "http://rdap.example/ip/1")


class EndpointTest(unittest.TestCase):
    def call(self, ip):
        return api.handle(None, {"q": "whois", "ip": ip})

    def test_private_and_reserved_are_refused_without_a_lookup(self):
        with mock.patch.object(rdap, "_fetch") as fetch:
            for ip in ("10.0.0.5", "192.168.1.20", "203.0.113.5", "::1", "nope"):
                self.assertEqual(self.call(ip)[0], 400, ip)
            fetch.assert_not_called()

    def test_lookup(self):
        with mock.patch.object(rdap, "_fetch", return_value=(
                "https://rdap.arin.net/registry/ip/8.0.0.1", ARIN)) as fetch:
            code, body = self.call("8.0.0.1")
        fetch.assert_called_once_with("https://rdap.arin.net/registry/ip/8.0.0.1")
        self.assertEqual(code, 200)
        self.assertEqual((body["ip"], body["abuse"]), ("8.0.0.1", ["abuse@example.net"]))

    def test_registry_errors(self):
        with mock.patch.object(rdap, "_fetch", side_effect=rdap.LookupFailed("rate limited")):
            self.assertEqual(self.call("8.0.0.1"), (502, {"error": "rate limited"}))
        with mock.patch.object(rdap, "_fetch", return_value=("u", {"objectClassName": "domain"})):
            self.assertEqual(self.call("8.0.0.1")[0], 502)


if __name__ == "__main__":
    unittest.main()
