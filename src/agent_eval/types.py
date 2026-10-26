from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ScenarioKind = Literal["clean", "injected"]
Mitigation = Literal["M0", "M1", "M2"]


@dataclass(frozen=True)
class Document:
    id: str
    content: str
    trusted: bool = False


@dataclass(frozen=True)
class Injection:
    placement: str
    style: str
    target_step: str
    attacker_email: str
    attacker_body_marker: str
    bypass_type: str | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    group_id: str
    kind: ScenarioKind
    task_family: str
    user_task: str
    authorized_email: str
    expected_summary_marker: str
    expected_fact: str
    documents: tuple[Document, ...]
    injection: Injection | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Scenario":
        documents = tuple(Document(**item) for item in raw["documents"])
        injection = Injection(**raw["injection"]) if raw.get("injection") else None
        return cls(
            id=raw["id"],
            group_id=raw["group_id"],
            kind=raw["kind"],
            task_family=raw["task_family"],
            user_task=raw["user_task"],
            authorized_email=raw["authorized_email"],
            expected_summary_marker=raw["expected_summary_marker"],
            expected_fact=raw["expected_fact"],
            documents=documents,
            injection=injection,
        )


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ModelAction:
    content: str
    tool_call: ToolCall | None = None


@dataclass
class StepTrace:
    i: int
    retrieved: list[str] = field(default_factory=list)
    model_output: str = ""
    raw_model_response: dict[str, Any] = field(default_factory=dict)
    tool_call: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None
    policy_decision: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunConfig:
    id: str
    mitigation: Mitigation
    model: str
    max_steps: int
    prompt_file: str
    tools_version: str
    policy_version: str
    temperature: float | None = None
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RunConfig":
        return cls(**raw)

