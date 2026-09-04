"""Tests for the HTTP Parameter Pollution Detector's Security Engine and
rules.

Rule-level tests use synthetic response dicts (no network calls). The
engine-level tests spin up a REAL local HTTP server (Python's http.server,
on an ephemeral localhost port) that reflects query parameters it receives
into its response, and perform a REAL HTTP request against it via the
actual ScanEngine/requests code path — genuine end-to-end HTTP testing
without touching any third-party site. Only a single, passive GET with an
appended, harmless, uniquely-marked duplicate parameter is ever sent.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, _build_test_url
from app.detection_rules import (
    rule_marker_reflected_in_body,
    rule_only_last_value_reflected,
    rule_only_first_value_reflected,
    rule_marker_reflected_in_redirect_location,
    rule_marker_reflected_in_set_cookie,
    rule_both_markers_reflected_together,
)


def resp(url="https://example.com/", headers=None, body_prefix="", marker_a="AAA", marker_b="BBB", status_code=200):
    headers = headers or {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    chain_locations = [headers_lower["location"]] if "location" in headers_lower else []
    chain_set_cookies = [headers_lower["set-cookie"]] if "set-cookie" in headers_lower else []
    return {
        "url": url, "status_code": status_code, "headers": headers,
        "headers_lower": headers_lower,
        "body_prefix": body_prefix, "marker_a": marker_a, "marker_b": marker_b,
        "chain_locations": chain_locations, "chain_set_cookies": chain_set_cookies,
    }


def test_build_test_url_preserves_existing_params_and_appends_duplicate():
    test_url, a, b = _build_test_url("https://example.com/search?q=shoes")
    parts = urlsplit(test_url)
    qs = parse_qs(parts.query)
    assert qs["q"] == ["shoes"]
    assert qs["hppcheck"] == [a, b]


def test_marker_reflected_in_body_flagged():
    result = rule_marker_reflected_in_body(resp(body_prefix="<p>value: AAA</p>", marker_a="AAA", marker_b="BBB"))
    assert result is not None
    assert result["rule_id"] == "HPP-001"


def test_no_marker_reflected_not_flagged():
    result = rule_marker_reflected_in_body(resp(body_prefix="<p>nothing here</p>"))
    assert result is None


def test_last_value_wins_flagged():
    result = rule_only_last_value_reflected(resp(body_prefix="value=BBB", marker_a="AAA", marker_b="BBB"))
    assert result is not None
    assert result["rule_id"] == "HPP-002"


def test_first_value_wins_flagged():
    result = rule_only_first_value_reflected(resp(body_prefix="value=AAA", marker_a="AAA", marker_b="BBB"))
    assert result is not None
    assert result["rule_id"] == "HPP-003"


def test_both_values_reflected_flagged():
    result = rule_both_markers_reflected_together(resp(body_prefix="values=[AAA, BBB]", marker_a="AAA", marker_b="BBB"))
    assert result is not None
    assert result["rule_id"] == "HPP-006"
    # HPP-002/003 should NOT fire when both are present
    assert rule_only_last_value_reflected(resp(body_prefix="values=[AAA, BBB]", marker_a="AAA", marker_b="BBB")) is None
    assert rule_only_first_value_reflected(resp(body_prefix="values=[AAA, BBB]", marker_a="AAA", marker_b="BBB")) is None


def test_marker_in_redirect_location_flagged():
    result = rule_marker_reflected_in_redirect_location(
        resp(headers={"Location": "https://example.com/next?ref=AAA"}, marker_a="AAA", marker_b="BBB", status_code=302)
    )
    assert result is not None
    assert result["rule_id"] == "HPP-004"


def test_marker_not_in_redirect_location_not_flagged():
    result = rule_marker_reflected_in_redirect_location(
        resp(headers={"Location": "https://example.com/next"}, marker_a="AAA", marker_b="BBB", status_code=302)
    )
    assert result is None


def test_marker_in_set_cookie_flagged_critical():
    result = rule_marker_reflected_in_set_cookie(resp(headers={"Set-Cookie": "session=AAA"}, marker_a="AAA", marker_b="BBB"))
    assert result is not None
    assert result["severity"] == "critical"


def test_marker_not_in_set_cookie_not_flagged():
    result = rule_marker_reflected_in_set_cookie(resp(headers={"Set-Cookie": "session=xyz123"}, marker_a="AAA", marker_b="BBB"))
    assert result is None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        values = qs.get("hppcheck", [])
        # Realistic "last value wins" server behavior: reflect only the
        # last duplicate value it received, plus set a cookie from it, and
        # redirect through an intermediate hop that also reflects it in
        # Location -- exercising HPP-001/002/004/005 end-to-end.
        last_value = values[-1] if values else ""
        if parts.path == "/" and last_value:
            self.send_response(302)
            self.send_header("Location", f"/done?ref={last_value}")
            self.send_header("Set-Cookie", f"lastseen={last_value}")
            self.end_headers()
            return
        ref_value = (parse_qs(parts.query).get("ref") or [last_value])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html><body>echo: {ref_value}</body></html>".encode())

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real request with a real appended
    duplicate parameter, real reflected response, real findings — against
    a local server we control (not a third party)."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "HPP-001" in rule_ids  # marker reflected
        assert "HPP-002" in rule_ids  # last-value-wins server behavior
        assert "HPP-005" in rule_ids  # marker reflected into Set-Cookie
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "HPP-000" for f in result["findings"])
