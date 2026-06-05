"""Pytest configuration: force AEGIS fully offline for the test suite.

The integration tests in this directory are the spec for AEGIS's promise -
each scenario must reach the right verdict. They are meant to run against the
deterministic offline backend (see test_scenarios.py docstring) so they are
fast, reproducible, and need zero Azure resources.

Without this file, a developer with a populated ``.env`` (Azure OpenAI,
Content Safety, App Insights, ...) would silently run the whole suite against
live Azure: every guardian would make a real model call, every verdict would
ship telemetry, and a 5-test run would take ~5 minutes and depend on network +
quota. That is exactly the kind of flakiness you do not want the day before a
demo.

We pin the offline configuration in ``os.environ`` *before* the first
``get_settings()`` call. Environment variables take precedence over ``.env`` in
pydantic-settings, so this overrides whatever credentials are on disk. We also
clear the cached Settings singleton in case anything imported it first.
"""

from __future__ import annotations

import os

# --- Force the deterministic, network-free configuration --------------------
# Highest-fidelity backend AEGIS would otherwise pick is Azure OpenAI; pin the
# offline mock so guardians use the deterministic heuristic and never hit the
# wire.
os.environ["AEGIS_FORCE_OFFLINE_MOCK"] = "true"

# Disable every outbound Azure integration so tests stay hermetic.
os.environ["AEGIS_ENABLE_AZURE_MONITOR"] = "false"
os.environ["AEGIS_ENABLE_FOUNDRY_TRACING"] = "false"
os.environ["AEGIS_ENABLE_DEFENDER_INGEST"] = "false"

# Blank out credentials so the has_* feature flags resolve to False and the
# Prompt Shields / telemetry clients stay in their labelled degraded modes.
for _key in (
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_CONTENT_SAFETY_ENDPOINT",
    "AZURE_CONTENT_SAFETY_KEY",
    "APPLICATIONINSIGHTS_CONNECTION_STRING",
    "AZURE_AI_FOUNDRY_CONNECTION_STRING",
):
    os.environ[_key] = ""

# Keep test output readable.
os.environ.setdefault("AEGIS_LOG_LEVEL", "WARNING")

# If anything already imported and cached the settings singleton, drop it so
# the offline environment above takes effect.
try:  # pragma: no cover - defensive
    from aegis.settings import get_settings

    get_settings.cache_clear()
except Exception:  # pragma: no cover
    pass
