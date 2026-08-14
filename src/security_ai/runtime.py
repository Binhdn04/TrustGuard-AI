from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Generic, TypeVar

from pydantic import ValidationError

from src.security_ai.contracts import AssistantOperation, ModelResponse, StrictModel

OutputT = TypeVar("OutputT", bound=StrictModel)


@dataclass(frozen=True, slots=True)
class InvocationMetric:
    provider: str | None
    model: str | None
    operation: AssistantOperation
    latency_ms: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    status: str
    error: str | None = None


@dataclass(slots=True)
class TurnBudget:
    max_calls: int = 4
    calls: int = 0
    synthesis_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def reserve(self, operation: AssistantOperation) -> None:
        if self.calls >= self.max_calls:
            raise BudgetExceededError("turn_call_budget_exhausted")
        if operation is AssistantOperation.SYNTHESIZE and self.synthesis_calls >= 1:
            raise BudgetExceededError("turn_synthesis_budget_exhausted")
        self.calls += 1
        if operation is AssistantOperation.SYNTHESIZE:
            self.synthesis_calls += 1


class BudgetExceededError(RuntimeError):
    pass


@dataclass(slots=True)
class RuntimeResult(Generic[OutputT]):
    output: OutputT | None
    status: str
    error: str | None = None


@dataclass(slots=True)
class SecurityAssistantRuntime:
    timeout_seconds: float = 12.0
    max_retries: int = 1
    budget: TurnBudget = field(default_factory=TurnBudget)
    metrics: list[InvocationMetric] = field(default_factory=list)

    async def invoke(
        self,
        operation: AssistantOperation,
        call: Callable[[], Any],
        output_type: type[OutputT],
    ) -> RuntimeResult[OutputT]:
        """Run safely; failures become a rules-only fallback, never an API error.

        Metrics deliberately contain no prompt, raw response, or reasoning text.
        """
        for attempt in range(self.max_retries + 1):
            try:
                # Retries are provider calls too and consume the same per-turn
                # budget. A synthesis is intentionally never called twice.
                self.budget.reserve(operation)
            except BudgetExceededError as exc:
                self._metric(operation, 0, "budget_exceeded", error=str(exc))
                return RuntimeResult(None, "fallback", str(exc))
            started = perf_counter()
            try:
                response = await asyncio.wait_for(call(), timeout=self.timeout_seconds)
                parsed = ModelResponse[output_type].model_validate(response)
                output = output_type.model_validate(parsed.output)
                self.budget.input_tokens += parsed.usage.input_tokens
                self.budget.output_tokens += parsed.usage.output_tokens
                self.budget.cost_usd += parsed.usage.cost_usd
                self._metric(operation, started, "ok", parsed)
                return RuntimeResult(output, "ok")
            except TimeoutError:
                error = "timeout"
            except (ValidationError, TypeError, ValueError):
                error = "invalid_structured_output"
            except Exception:  # provider errors are normalized and never leak details
                error = "provider_error"
            self._metric(operation, started, error, error=error)
            if attempt < self.max_retries:
                continue
            return RuntimeResult(None, "fallback", error)
        return RuntimeResult(None, "fallback", "provider_error")

    def _metric(
        self,
        operation: AssistantOperation,
        started: float,
        status: str,
        response: ModelResponse[Any] | None = None,
        error: str | None = None,
    ) -> None:
        usage = response.usage if response else None
        self.metrics.append(
            InvocationMetric(
                provider=response.provider if response else None,
                model=response.model if response else None,
                operation=operation,
                latency_ms=round((perf_counter() - started) * 1000) if started else 0,
                input_tokens=usage.input_tokens if usage else 0,
                output_tokens=usage.output_tokens if usage else 0,
                cost_usd=usage.cost_usd if usage else 0.0,
                status=status,
                error=error,
            )
        )
