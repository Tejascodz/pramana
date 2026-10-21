"""Check modules. Importing this package registers every check."""

from pramana.checks import (  # noqa: F401
    agent_trace,
    calibration,
    data_quality,
    documentation,
    drift,
    explainability,
    fairness,
    governance,
    llm,
    meta,
    performance,
    privacy,
    robustness,
)
