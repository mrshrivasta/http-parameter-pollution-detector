"""
Security Engine — HTTP Parameter Pollution Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide and
inspects the actual response headers/body returned by that server. Nothing
is simulated: if the target is unreachable, that is reported as a real
error, not silently faked.

SAFETY / SCOPE: This engine issues exactly ONE real, standard, idempotent
GET request per scan. The only modification made to the URL you provide is
appending a single, harmless, uniquely-marked query parameter TWICE with
two different marker values (e.g. ?hppcheck=MARKER_A&hppcheck=MARKER_B).
This is the same non-destructive technique used by well-known scanners
(OWASP ZAP, Burp Suite's passive/light-active scans) to observe how a
server resolves duplicate parameters. No existing parameter values are
ever modified, no exploit payloads (script tags, SQL syntax, etc.) are
ever sent, and no repeated/high-volume requests are made.
"""
import time
import uuid
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import requests

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "HttpParameterPollutionDetector/1.0 (+https://github.com/mrshrivasta; educational security tool)"

MARKER_PARAM = "hppcheck"


def _build_test_url(target_url):
    """Append hppcheck=<A> and hppcheck=<B> to the query string, preserving
    every existing query parameter untouched. A and B are short,
    unguessable per-scan markers so any reflection in the response body
    can be attributed with confidence to this specific request."""
    marker_a = "A" + uuid.uuid4().hex[:8]
    marker_b = "B" + uuid.uuid4().hex[:8]
    parts = urlsplit(target_url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    new_query_pairs = existing + [(MARKER_PARAM, marker_a), (MARKER_PARAM, marker_b)]
    new_query = urlencode(new_query_pairs)
    test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    return test_url, marker_a, marker_b


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0

    def _fetch(self):
        test_url, marker_a, marker_b = _build_test_url(self.target_url)
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        resp = requests.get(
            test_url, headers=headers, timeout=self.timeout,
            verify=self.verify_tls, allow_redirects=True, stream=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body_prefix = ""
        try:
            body_prefix = next(resp.iter_content(chunk_size=4096, decode_unicode=False), b"").decode("utf-8", errors="replace")
        except Exception:
            body_prefix = ""
        try:
            raw_header_pairs = list(resp.raw.headers.items())
        except Exception:
            raw_header_pairs = list(resp.headers.items())
        # requests follows redirects by default, which means an
        # intermediate hop's Location/Set-Cookie header (where a reflected
        # marker would actually show up) would otherwise be lost once we
        # only look at the final response. Capture every hop's headers too.
        chain_locations = []
        chain_set_cookies = []
        for hop in list(resp.history) + [resp]:
            hop_headers_lower = {k.lower(): v for k, v in hop.headers.items()}
            if "location" in hop_headers_lower:
                chain_locations.append(hop_headers_lower["location"])
            if "set-cookie" in hop_headers_lower:
                chain_set_cookies.append(hop_headers_lower["set-cookie"])
        result = {
            "url": resp.url,
            "requested_url": test_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "headers_lower": headers_lower,
            "raw_header_pairs": raw_header_pairs,
            "body_prefix": body_prefix,
            "marker_a": marker_a,
            "marker_b": marker_b,
            "chain_locations": chain_locations,
            "chain_set_cookies": chain_set_cookies,
            "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
        }
        resp.close()
        return result

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    result["file_path"] = response["url"]
                    result["permissions_octal"] = str(response["status_code"])
                    result["owner_uid"] = None
                    result["owner_gid"] = None
                    findings.append(result)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "HPP-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["headers"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }
