"""
In-memory caches for AI analysis to avoid re-prompting the same endpoints.

Three independent caches, all workspace-scoped:
1. SuggestCache — memoises haiku suggestion results (FIFO, 500 max)
2. TriageState — tracks which endpoints have been analysed + prior context
3. PreviewCache — bridges the gap between Preview click and Run Triage (60s TTL)
"""

import hashlib
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ── Suggest Cache ────────────────────────────────────────────────

_SUGGEST_MAX = 500

# Global ordered dict: cache_key → suggestions list
_suggest_cache: OrderedDict[str, list] = OrderedDict()


def _suggest_key(workspace_id: str, text: str, field_type: str,
                 field_name: str, method: str, url: str,
                 is_json_value: bool = False) -> str:
    """Build a deterministic cache key for a suggestion request."""
    raw = f"{workspace_id}|{field_type}|{field_name}|{method}|{url}|{is_json_value}|{text}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def get_cached_suggestion(workspace_id: str, text: str, field_type: str,
                          field_name: str, method: str, url: str,
                          is_json_value: bool = False) -> list | None:
    """Return cached suggestions or None on miss."""
    key = _suggest_key(workspace_id, text, field_type, field_name, method, url, is_json_value)
    result = _suggest_cache.get(key)
    if result is not None:
        # Move to end (most-recently-used)
        _suggest_cache.move_to_end(key)
        log.debug("Suggest cache HIT for key %s", key[:8])
    return result


def set_cached_suggestion(workspace_id: str, text: str, field_type: str,
                          field_name: str, method: str, url: str,
                          suggestions: list,
                          is_json_value: bool = False) -> None:
    """Store suggestions in the cache, evicting oldest if full."""
    key = _suggest_key(workspace_id, text, field_type, field_name, method, url, is_json_value)
    _suggest_cache[key] = suggestions
    _suggest_cache.move_to_end(key)
    while len(_suggest_cache) > _SUGGEST_MAX:
        _suggest_cache.popitem(last=False)


def _clear_suggest_cache_for_workspace(workspace_id: str) -> None:
    """Remove all suggest cache entries for a workspace (prefix match on key)."""
    # Keys are hashed so we can't prefix-filter — just clear all.
    # This is acceptable because it's a small FIFO cache.
    _suggest_cache.clear()


# ── Triage State ─────────────────────────────────────────────────

@dataclass
class TriageState:
    """Tracks which endpoints have already been sent to Claude for triage."""
    analyzed_keys: set = field(default_factory=set)   # "GET /api/users", ...
    prior_summary: str = ""
    prior_findings: list = field(default_factory=list)
    prior_upload_endpoints: list = field(default_factory=list)
    prior_priority_targets: list = field(default_factory=list)
    last_host_filter: str = ""
    last_confirmed_vuln_count: int = 0
    last_scan_coverage_count: int = 0


_triage_states: dict[str, TriageState] = {}


def get_triage_state(workspace_id: str) -> TriageState:
    """Get or create the triage state for a workspace."""
    if workspace_id not in _triage_states:
        _triage_states[workspace_id] = TriageState()
    return _triage_states[workspace_id]


def partition_endpoints(workspace_id: str, endpoints: list[dict],
                        host_filter: str) -> tuple[list[dict], int]:
    """Partition endpoints into (new_endpoints, already_analyzed_count).

    If host_filter changed since last triage, resets state (full re-analyse).
    """
    state = get_triage_state(workspace_id)

    # Host filter changed → reset
    if host_filter != state.last_host_filter:
        log.info("Host filter changed (%s → %s), resetting triage state",
                 state.last_host_filter, host_filter)
        _triage_states[workspace_id] = TriageState()
        state = _triage_states[workspace_id]
        state.last_host_filter = host_filter
        return endpoints, 0

    new_eps = []
    cached_count = 0
    for ep in endpoints:
        key = f"{ep.get('method', 'GET')} {ep.get('path', '')}"
        if key in state.analyzed_keys:
            cached_count += 1
        else:
            new_eps.append(ep)

    log.info("Endpoint partition: %d new, %d already analysed", len(new_eps), cached_count)
    return new_eps, cached_count


def update_triage_state(workspace_id: str, new_endpoint_keys: list[str],
                        summary: str, findings: list,
                        upload_endpoints: list, priority_targets: list,
                        host_filter: str,
                        confirmed_vuln_count: int = 0,
                        scan_coverage_count: int = 0) -> None:
    """Update state after a successful triage run."""
    state = get_triage_state(workspace_id)
    state.analyzed_keys.update(new_endpoint_keys)
    state.prior_summary = summary
    state.prior_findings = findings
    state.prior_upload_endpoints = upload_endpoints
    state.prior_priority_targets = priority_targets
    state.last_host_filter = host_filter
    state.last_confirmed_vuln_count = confirmed_vuln_count
    state.last_scan_coverage_count = scan_coverage_count
    log.info("Triage state updated: %d total endpoints cached", len(state.analyzed_keys))


# ── Preview Cache ────────────────────────────────────────────────

_PREVIEW_TTL = 60.0  # seconds

@dataclass
class PreviewCache:
    """Stores prepared data from /ai/preview to avoid re-fetching in /ai/triage."""
    endpoints: list
    confirmed_vulns: list
    scan_coverage: list
    host_filter: str
    timestamp: float = field(default_factory=time.time)


_preview_caches: dict[str, PreviewCache] = {}


def set_preview_cache(workspace_id: str, cache: PreviewCache) -> None:
    """Store preview-prepared data for consumption by triage."""
    _preview_caches[workspace_id] = cache


def consume_preview_cache(workspace_id: str, host_filter: str) -> PreviewCache | None:
    """Pop and return preview cache if it exists, isn't expired, and filter matches."""
    cache = _preview_caches.pop(workspace_id, None)
    if cache is None:
        return None
    if time.time() - cache.timestamp > _PREVIEW_TTL:
        log.debug("Preview cache expired (%.1fs old)", time.time() - cache.timestamp)
        return None
    if cache.host_filter != host_filter:
        log.debug("Preview cache filter mismatch (%s vs %s)", cache.host_filter, host_filter)
        return None
    log.info("Preview cache consumed (%d endpoints, %.1fs old)",
             len(cache.endpoints), time.time() - cache.timestamp)
    return cache


# ── Global Operations ────────────────────────────────────────────

def clear_workspace_cache(workspace_id: str) -> None:
    """Clear all caches for a given workspace."""
    _triage_states.pop(workspace_id, None)
    _preview_caches.pop(workspace_id, None)
    _clear_suggest_cache_for_workspace(workspace_id)
    log.info("Cleared all AI caches for workspace %s", workspace_id)


def clear_all_caches() -> None:
    """Nuclear option — clear everything."""
    _suggest_cache.clear()
    _triage_states.clear()
    _preview_caches.clear()
    log.info("Cleared ALL AI caches")


def get_cache_stats(workspace_id: str) -> dict:
    """Return cache statistics for the given workspace."""
    state = _triage_states.get(workspace_id)
    preview = _preview_caches.get(workspace_id)
    return {
        "suggest_cached": len(_suggest_cache),
        "triage_endpoints_analyzed": len(state.analyzed_keys) if state else 0,
        "triage_has_prior_context": bool(state and state.prior_summary),
        "preview_cached": preview is not None and (time.time() - preview.timestamp) <= _PREVIEW_TTL,
    }
