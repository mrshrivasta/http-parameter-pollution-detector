"""
Detection Rules — HTTP Parameter Pollution Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects the REAL response headers/body from a single, passive
HTTP GET request in which a harmless, uniquely-marked query parameter was
appended TWICE (see app/security_engine). No exploit payloads are ever
sent — only two random, inert marker values appended as an extra
parameter, the same non-destructive technique used by well-known passive
web scanners to observe duplicate-parameter handling.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _body(response):
    return response.get("body_prefix") or ""


def rule_marker_reflected_in_body(response):
    """HPP-001: One (or both) of the injected duplicate-parameter marker
    values is reflected verbatim in the response body. This confirms the
    application echoes query parameter values into output, which is the
    prerequisite condition for parameter-pollution-driven reflected
    injection issues (XSS, HTML injection) when combined with insufficient
    output encoding."""
    body = _body(response)
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    hits = [m for m in (a, b) if m and m in body]
    if hits:
        return {
            "rule_id": "HPP-001",
            "rule_name": "Duplicate Parameter Marker Reflected in Response Body",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} reflected the injected marker value(s) "
                f"{hits} verbatim in the response body. The application "
                f"echoes query-parameter values into output; verify output "
                f"encoding is applied everywhere this parameter is used."
            ),
        }
    return None


def rule_only_last_value_reflected(response):
    """HPP-002 (informational): Only the SECOND (last) of the two
    duplicate marker values was reflected. This discloses that the
    application (or an intermediary in front of it) resolves duplicate
    parameters using 'last value wins' semantics — useful reconnaissance
    for predicting how a real pollution payload would be interpreted."""
    body = _body(response)
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    if a and b and b in body and a not in body:
        return {
            "rule_id": "HPP-002",
            "rule_name": "Duplicate Parameters Resolved as 'Last Value Wins'",
            "severity": SEVERITY_LOW,
            "description": (
                f"{response['url']} reflected only the second duplicate "
                f"parameter value, indicating 'last value wins' parsing. "
                f"Different components (WAF, app server, back-end) in the "
                f"same stack sometimes disagree on this, which is the core "
                f"mechanism HTTP Parameter Pollution attacks exploit."
            ),
        }
    return None


def rule_only_first_value_reflected(response):
    """HPP-003 (informational): Only the FIRST of the two duplicate marker
    values was reflected, indicating 'first value wins' parsing — the
    mirror image of HPP-002, and equally useful reconnaissance."""
    body = _body(response)
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    if a and b and a in body and b not in body:
        return {
            "rule_id": "HPP-003",
            "rule_name": "Duplicate Parameters Resolved as 'First Value Wins'",
            "severity": SEVERITY_LOW,
            "description": (
                f"{response['url']} reflected only the first duplicate "
                f"parameter value, indicating 'first value wins' parsing. "
                f"Different components in the same stack sometimes "
                f"disagree on this, which is the core mechanism HTTP "
                f"Parameter Pollution attacks exploit."
            ),
        }
    return None


def rule_marker_reflected_in_redirect_location(response):
    """HPP-004: The Location header of a redirect response (anywhere in
    the real redirect chain that was actually followed) contains one of
    the injected marker values. If a real (attacker-controlled) parameter
    value could reach this same sink unsanitized, this is a strong signal
    for a parameter-pollution-assisted open-redirect vulnerability."""
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    locations = response.get("chain_locations") or ([response["headers_lower"]["location"]] if "location" in response["headers_lower"] else [])
    for location in locations:
        if location and any(m and m in location for m in (a, b)):
            return {
                "rule_id": "HPP-004",
                "rule_name": "Injected Marker Reflected in Redirect Location Header",
                "severity": SEVERITY_HIGH,
                "description": (
                    f"{response['url']} was reached via a redirect whose "
                    f"Location header ('{location}') contains the injected "
                    f"marker value. A polluted/duplicated redirect-target "
                    f"parameter reaching this sink unsanitized is a real "
                    f"open-redirect risk pattern."
                ),
            }
    return None


def rule_marker_reflected_in_set_cookie(response):
    """HPP-005: A Set-Cookie header value (anywhere in the real redirect
    chain that was actually followed) contains one of the injected marker
    values. Query-parameter values flowing directly into a cookie value is
    a serious pattern — combined with parameter pollution, it can enable
    cookie/session-value injection or fixation."""
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    set_cookies = response.get("chain_set_cookies") or ([response["headers_lower"]["set-cookie"]] if "set-cookie" in response["headers_lower"] else [])
    for set_cookie in set_cookies:
        if set_cookie and any(m and m in set_cookie for m in (a, b)):
            return {
                "rule_id": "HPP-005",
                "rule_name": "Injected Marker Reflected in Set-Cookie Header",
                "severity": SEVERITY_CRITICAL,
                "description": (
                    f"{response['url']} (or a hop in its redirect chain) "
                    f"set a cookie whose value contains the injected "
                    f"marker. A query parameter flowing directly into a "
                    f"cookie value is a serious injection/fixation-adjacent "
                    f"pattern, especially when duplicate parameters are "
                    f"involved."
                ),
            }
    return None


def rule_both_markers_reflected_together(response):
    """HPP-006: BOTH duplicate marker values appear in the response body
    at once (e.g. concatenated into an array/list). This shows the
    application collects all duplicate values into a collection rather
    than picking one, which changes the pollution attack surface — a
    single 'expected' parameter can be turned into an unexpected list,
    which has caused real logic-bypass vulnerabilities in frameworks that
    silently accept arrays where a scalar was expected."""
    body = _body(response)
    a, b = response.get("marker_a", ""), response.get("marker_b", "")
    if a and b and a in body and b in body:
        return {
            "rule_id": "HPP-006",
            "rule_name": "Both Duplicate Parameter Values Reflected (Array-Style Handling)",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{response['url']} reflected BOTH duplicate marker "
                f"values, indicating the application collects duplicate "
                f"parameters into an array/list rather than picking one. "
                f"Review any downstream logic that assumes this parameter "
                f"is always a single scalar value."
            ),
        }
    return None


ALL_RULES = [
    rule_marker_reflected_in_body,
    rule_only_last_value_reflected,
    rule_only_first_value_reflected,
    rule_marker_reflected_in_redirect_location,
    rule_marker_reflected_in_set_cookie,
    rule_both_markers_reflected_together,
]
