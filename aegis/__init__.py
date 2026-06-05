"""AEGIS - the SOC for agent swarms.

Cross-agent correlation and arbitration layer that sits above Microsoft's
single-point AI security sensors (Prompt Shields, Entra Agent ID, Defender
for AI). Detection unit is the cross-agent sequence, not the single call.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aegis")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
