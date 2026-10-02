"""WHOIS lookups over RDAP, the JSON successor to port-43 WHOIS.

Each regional internet registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) runs
an RDAP server for its own address space. IANA's bootstrap file, bundled as
rdap_bootstrap.json, says which registry holds an address. Registries redirect
to national registries (KRNIC, registro.br, ...) themselves.

Only called when someone opens the WHOIS section for an IP, so the only
outbound traffic is one HTTPS request per IP looked up.
"""
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FALLBACK = "https://rdap.org/"  # redirects to the right registry
MAX_BYTES = 2 << 20
TIMEOUT = 12

REGISTRIES = {"rdap.arin.net": "ARIN", "rdap.db.ripe.net": "RIPE NCC",
              "rdap.apnic.net": "APNIC", "rdap.lacnic.net": "LACNIC",
              "rdap.afrinic.net": "AFRINIC", "krnic.rdap.apnic.net": "KRNIC",
              "rdap.registro.br": "NIC.br", "jpnic.rdap.apnic.net": "JPNIC",
              "twnic.rdap.apnic.net": "TWNIC", "rdap.cnnic.cn": "CNNIC"}
_EMAIL = re.compile(r"^[^\s@<>()\[\],;:\"]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


class LookupFailed(Exception):
    pass


_bootstrap = None


def _services():
    global _bootstrap
    if _bootstrap is None:
        with open(os.path.join(HERE, "rdap_bootstrap.json"), encoding="utf-8") as f:
            d = json.load(f)
        _bootstrap = [(ipaddress.ip_network(p), url)
                      for fam in ("ipv4", "ipv6") for url, prefixes in d[fam] for p in prefixes]
    return _bootstrap


def server_for(ip):
    addr = ipaddress.ip_address(ip)
    best = None
    for net, url in _services():
        if net.version == addr.version and addr in net:
            if best is None or net.prefixlen > best[0].prefixlen:
                best = (net, url)
    return best[1] if best else FALLBACK


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise LookupFailed("registry redirected to a non-HTTPS address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url):
    """GET url, following HTTPS redirects. Returns (final_url, parsed JSON)."""
    opener = urllib.request.build_opener(_HttpsOnly)
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json", "User-Agent": "syno-secdash"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES + 1)
            final = resp.geturl()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise LookupFailed("the registry has no record for this address")
        if e.code == 429:
            raise LookupFailed("the registry is rate limiting lookups; try again in a minute")
        raise LookupFailed("the registry answered HTTP %d" % e.code)
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise LookupFailed("couldn't reach the registry (%s)" % reason)
    if len(raw) > MAX_BYTES:
        raise LookupFailed("the registry's answer was too large")
    try:
        return final, json.loads(raw.decode("utf-8"))
    except ValueError:
        raise LookupFailed("the registry's answer wasn't valid RDAP")


def _vcard(entity):
    out = {"name": None, "kind": None, "emails": [], "phones": [], "address": None}
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
        return out
    for item in card[1]:
        if not (isinstance(item, list) and len(item) >= 4):
            continue
        prop, params, value = item[0], item[1] if isinstance(item[1], dict) else {}, item[3]
        if prop == "fn" and isinstance(value, str):
            out["name"] = value.strip()
        elif prop == "kind" and isinstance(value, str):
            out["kind"] = value
        elif prop == "email" and isinstance(value, str) and _EMAIL.match(value.strip()):
            out["emails"].append(value.strip())
        elif prop == "tel" and isinstance(value, str):
            out["phones"].append(re.sub(r"^tel:", "", value.strip()))
        elif prop == "adr":
            label = params.get("label")
            if isinstance(label, str) and label.strip():
                out["address"] = " ".join(label.split())
            elif isinstance(value, list):
                parts = [v for v in value if isinstance(v, str) and v.strip()]
                parts += [x for v in value if isinstance(v, list) for x in v if isinstance(x, str)]
                out["address"] = ", ".join(p.strip() for p in parts if p.strip()) or None
    return out


def _entities(ents, depth=0):
    """Flatten nested entities (ARIN nests abuse contacts inside the organisation)."""
    for e in ents or []:
        if isinstance(e, dict):
            yield e
            if depth < 3:
                yield from _entities(e.get("entities"), depth + 1)


def _uniq(items):
    seen, out = set(), []
    for x in items:
        if x and x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out


def summarize(data, url=""):
    """Reduce an RDAP ip-network object to what the IP drawer shows."""
    contacts, by_handle = [], {}
    for e in _entities(data.get("entities")):
        roles = [r for r in e.get("roles") or [] if isinstance(r, str)]
        card = _vcard(e)
        key = e.get("handle") or card["name"]
        if key in by_handle:  # same contact listed twice (RIPE repeats the abuse-c)
            c = by_handle[key]
            c["roles"] = _uniq(c["roles"] + roles)
            continue
        c = dict(card, handle=e.get("handle"), roles=roles)
        by_handle[key] = c
        contacts.append(c)
    for c in contacts:
        c["emails"] = _uniq(c["emails"])
        c["phones"] = _uniq(c["phones"])

    remarks = []
    for r in data.get("remarks") or []:
        desc = [d for d in (r.get("description") or []) if isinstance(d, str)]
        if desc:
            remarks.append({"title": r.get("title") if isinstance(r.get("title"), str) else None,
                            "text": "\n".join(desc)[:2000]})

    abuse = _uniq([m for c in contacts if "abuse" in c["roles"] for m in c["emails"]])
    abuse_source = "abuse" if abuse else None
    if not abuse:  # some APNIC/AFRINIC records only mention it in remarks
        abuse = _uniq([m for r in remarks for m in _EMAIL_IN_TEXT.findall(r["text"])
                       if "abuse" in m.lower() or "abuse" in (r["title"] or "").lower()])
        abuse_source = "remarks" if abuse else None
    if not abuse:
        abuse = _uniq([m for c in contacts if set(c["roles"]) & {"technical", "noc"}
                       for m in c["emails"]] +
                      [m for c in contacts for m in c["emails"]])
        abuse_source = "other" if abuse else None

    org = next((c["name"] for c in contacts
                if "registrant" in c["roles"] and c["kind"] == "org" and c["name"]), None)
    org = org or next((r["text"].split("\n")[0] for r in remarks
                       if (r["title"] or "").lower() == "description"), None)
    org = org or next((c["name"] for c in contacts
                       if "registrant" in c["roles"] and c["name"]
                       and not c["name"].upper().endswith("-MNT")), None)

    events = {}
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and isinstance(ev.get("eventDate"), str):
            events[ev.get("eventAction")] = ev["eventDate"]
    cidrs = []
    for c in data.get("cidr0_cidrs") or []:
        if isinstance(c, dict) and (c.get("v4prefix") or c.get("v6prefix")):
            cidrs.append("%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length")))
    host = re.sub(r"^https://([^/:]+).*$", r"\1", url or "").lower()
    link = next((l.get("href") for l in data.get("links") or []
                 if isinstance(l, dict) and l.get("rel") == "self"
                 and str(l.get("href", "")).startswith("https://")), None)
    start, end = data.get("startAddress"), data.get("endAddress")
    return {
        "registry": REGISTRIES.get(host, host or None),
        "source": url or None,
        "link": link or (url or None),
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "range": "%s – %s" % (start, end) if start and end else None,
        "cidrs": cidrs,
        "parent": data.get("parentHandle"),
        "org": org,
        "registered": events.get("registration"),
        "updated": events.get("last changed"),
        "abuse": abuse,
        "abuse_source": abuse_source,
        "contacts": [{k: c[k] for k in ("name", "handle", "roles", "kind", "emails", "phones",
                                        "address")}
                     for c in contacts
                     if c["emails"] or c["kind"] in ("org", "group")][:12],
        "remarks": remarks[:8],
        "port43": data.get("port43"),
    }


def lookup(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("not an IP address")
    if not addr.is_global:
        raise ValueError("%s is a private or reserved address; it has no public WHOIS record" % ip)
    url, data = _fetch(server_for(ip) + "ip/" + str(addr))
    if not isinstance(data, dict) or data.get("objectClassName") not in (None, "ip network"):
        raise LookupFailed("the registry's answer wasn't an IP network record")
    return dict(summarize(data, url), ip=str(addr))
