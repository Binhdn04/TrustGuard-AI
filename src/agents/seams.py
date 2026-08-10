from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from src.agents.contracts import (
    CampaignDetectionOutput,
    ExplanationOutput,
    LiveStepTransition,
    ProvisionalWarning,
    RiskAssessmentOutput,
)


class ProgressSink(Protocol):
    async def emit(self, transition: LiveStepTransition) -> None: ...


class ProvisionalWarningSink(Protocol):
    async def emit(self, warning: ProvisionalWarning) -> None: ...


class RiskEngine(Protocol):
    def assess(self, state: Mapping[str, Any]) -> RiskAssessmentOutput: ...


class ExplanationEngine(Protocol):
    def explain(self, state: Mapping[str, Any]) -> ExplanationOutput: ...


class CampaignDetector(Protocol):
    async def detect(self, state: Mapping[str, Any]) -> CampaignDetectionOutput: ...


class NullProgressSink:
    async def emit(self, transition: LiveStepTransition) -> None:
        del transition


class NullProvisionalWarningSink:
    async def emit(self, warning: ProvisionalWarning) -> None:
        del warning


class NullCampaignDetector:
    async def detect(self, state: Mapping[str, Any]) -> CampaignDetectionOutput:
        del state
        return {}


@dataclass(frozen=True, slots=True)
class FunctionRiskEngine:
    function: Callable[[Mapping[str, Any]], RiskAssessmentOutput]

    def assess(self, state: Mapping[str, Any]) -> RiskAssessmentOutput:
        return self.function(state)


@dataclass(frozen=True, slots=True)
class FunctionExplanationEngine:
    function: Callable[[Mapping[str, Any]], ExplanationOutput]

    def explain(self, state: Mapping[str, Any]) -> ExplanationOutput:
        return self.function(state)


__all__ = [
    "CampaignDetector",
    "ExplanationEngine",
    "FunctionExplanationEngine",
    "FunctionRiskEngine",
    "NullCampaignDetector",
    "NullProgressSink",
    "NullProvisionalWarningSink",
    "ProgressSink",
    "ProvisionalWarningSink",
    "RiskEngine",
]
