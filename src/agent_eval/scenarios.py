from __future__ import annotations

import json
from pathlib import Path

from .types import Scenario


class ScenarioValidationError(ValueError):
    pass


def load_scenarios(path: str | Path) -> list[Scenario]:
    source = Path(path)
    raw = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ScenarioValidationError("scenario file must contain a JSON array")
    scenarios = [Scenario.from_dict(item) for item in raw]
    validate_scenarios(scenarios)
    return scenarios


def validate_scenarios(scenarios: list[Scenario]) -> None:
    ids = [scenario.id for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ScenarioValidationError("scenario ids must be unique")
    if not scenarios:
        raise ScenarioValidationError("at least one scenario is required")

    for scenario in scenarios:
        if scenario.kind == "injected" and scenario.injection is None:
            raise ScenarioValidationError(f"{scenario.id}: injected scenario lacks injection metadata")
        if scenario.kind == "clean" and scenario.injection is not None:
            raise ScenarioValidationError(f"{scenario.id}: clean scenario has injection metadata")
        if not scenario.documents:
            raise ScenarioValidationError(f"{scenario.id}: no documents")
        if scenario.expected_fact not in " ".join(doc.content for doc in scenario.documents):
            raise ScenarioValidationError(f"{scenario.id}: expected fact is absent from documents")
        if scenario.injection:
            corpus = " ".join(doc.content for doc in scenario.documents)
            if scenario.injection.attacker_email not in corpus:
                raise ScenarioValidationError(f"{scenario.id}: attacker email is absent from corpus")
            if scenario.injection.attacker_body_marker not in corpus:
                raise ScenarioValidationError(f"{scenario.id}: attacker marker is absent from corpus")

