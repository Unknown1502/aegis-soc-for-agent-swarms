"""AEGIS API server.

Streams actions / signals / verdicts / outcomes / trust changes / threshold
changes to the dashboard via WebSocket. Also exposes REST endpoints to
trigger the demo attacks on demand (so the live URL judges visit can replay
each scenario), retrieve the audit chain, verify chain integrity, and read
the live metrics snapshot.
"""

from aegis.api.server import build_app, run

__all__ = ["build_app", "run"]
