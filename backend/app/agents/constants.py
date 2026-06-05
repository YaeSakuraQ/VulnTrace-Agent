"""Shared tool classification constants used across the agent layer.

These are kept in a separate module to avoid circular imports between
graph.py, planner.py, and report_agent.py.
"""

from __future__ import annotations

# High-risk verification / exploit primitives that should stop the graph
# immediately on failure (before reproduction).
VERIFICATION_TOOLS: frozenset[str] = frozenset({"vuln_verify", "header_mutation", "raw_http", "tcp_send"})

# Extended set that includes all exploit-class tools including http_request
# (used for heuristic finalize and report evidence filtering).
EXPLOIT_TOOLS: frozenset[str] = frozenset({"vuln_verify", "header_mutation", "raw_http", "tcp_send", "http_request"})
