"""Configuration surface.

Every tunable the analysis depends on lives here, sourced from environment
variables with documented defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(ValueError):
    """Raised when configuration is present but unusable."""


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    """Runtime configuration for a reachability run."""

    # Hop limits reported. A hop is one privilege escalation step: assuming a
    # role, attaching a policy to yourself, passing a role to a service that
    # will run your code. Three is the default ceiling because beyond that the
    # paths stop being explainable to the person who has to fix them.
    max_hops: int = field(default_factory=lambda: _env_int("IBR_MAX_HOPS", 3))

    # Paths enumerated per principal before the search stops. A principal with
    # thousands of distinct paths to admin needs remediation, not a longer list.
    max_paths_per_principal: int = field(default_factory=lambda: _env_int("IBR_MAX_PATHS", 25))

    # Seed for every random path, so a generated account is reproducible.
    seed: int = field(default_factory=lambda: _env_int("IBR_SEED", 7))

    # When true, an edge that depends on a condition key the evaluator does not
    # implement is included and flagged rather than dropped. See ADR-003: the
    # tool over reports reachability rather than under reporting it, because a
    # missed path is a breach and a spurious one is ten minutes of checking.
    assume_conditions_satisfiable: bool = field(
        default_factory=lambda: _env_bool("IBR_ASSUME_CONDITIONS", True)
    )

    def __post_init__(self) -> None:
        if not 1 <= self.max_hops <= 10:
            raise ConfigError(f"max_hops must be in [1, 10], got {self.max_hops}")
        if self.max_paths_per_principal < 1:
            raise ConfigError(
                f"max_paths_per_principal must be at least 1, got {self.max_paths_per_principal}"
            )


def load_config() -> Config:
    """Build a Config from the environment."""
    return Config()
