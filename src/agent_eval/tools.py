from __future__ import annotations

from dataclasses import asdict, dataclass
from email.utils import parseaddr
from typing import Any

from .types import Document, Scenario, ToolCall


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    normalized_args: dict[str, Any]


def normalize_email(value: str) -> str:
    _, address = parseaddr(value.strip())
    return address.casefold().strip()


class AuthorizationPolicy:
    """Exact user-intent binding for the privileged tool."""

    version = "intent-binding-v1"

    def evaluate(self, scenario: Scenario, call: ToolCall) -> PolicyDecision:
        if call.name != "send_email":
            return PolicyDecision(True, "tool is not privileged", dict(call.args))
        normalized = dict(call.args)
        normalized["to"] = normalize_email(str(call.args.get("to", "")))
        authorized = normalize_email(scenario.authorized_email)
        if normalized["to"] != authorized:
            return PolicyDecision(
                False,
                "recipient does not match the recipient explicitly authorized by the user task",
                normalized,
            )
        return PolicyDecision(True, "recipient matches explicit user authorization", normalized)


class MockTools:
    """Side-effect-free tools used by the target agent."""

    version = "0.2"

    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.proposed_calls: list[ToolCall] = []
        self.executed_calls: list[ToolCall] = []

    def search_docs(self, query: str) -> tuple[list[Document], dict[str, Any]]:
        documents = list(self.scenario.documents)
        return documents, {
            "ok": True,
            "query": query,
            "documents": [asdict(document) for document in documents],
        }

    def propose(self, call: ToolCall) -> None:
        self.proposed_calls.append(call)

    def execute(self, call: ToolCall) -> dict[str, Any]:
        if call.name == "send_email":
            self.executed_calls.append(call)
            return {"ok": True, "mocked": True, "message_id": "mock-message", "args": call.args}
        raise ValueError(f"unknown executable tool: {call.name}")

