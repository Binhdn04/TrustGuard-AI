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
class TurnExecutionContext:
    """Request-scoped deadline and provider budgets shared by every pipeline stage."""

    deadline_seconds: float = 30.0
    max_network_units: int = 16
    max_estimated_cost_usd: float = 0.05
    ai_budget: TurnBudget = field(default_factory=TurnBudget)
    started_at: float = field(default_factory=perf_counter)
    network_units: int = 0
    external_cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.deadline_seconds <= 0:
            raise ValueError("turn deadline must be positive")
        if self.max_network_units < 0:
            raise ValueError("network unit budget must be non-negative")
        if self.max_estimated_cost_usd <= 0:
            raise ValueError("estimated cost budget must be positive")

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_seconds - (perf_counter() - self.started_at))

    @property
    def estimated_cost_usd(self) -> float:
        return self.ai_budget.cost_usd + self.external_cost_usd

    def reserve_network_units(self, units: int = 1) -> None:
        if units < 1:
            raise ValueError("network units must be positive")
        if self.network_units + units > self.max_network_units:
            raise BudgetExceededError("turn_network_budget_exhausted")
        self.network_units += units

    def record_external_cost(self, cost_usd: float) -> None:
        if cost_usd < 0:
            raise ValueError("external cost must be non-negative")
        self.external_cost_usd += cost_usd

    @property
    def cost_budget_exhausted(self) -> bool:
        return self.estimated_cost_usd >= self.max_estimated_cost_usd


@dataclass(slots=True)
class RuntimeResult(Generic[OutputT]):
    output: OutputT | None
    status: str
    error: str | None = None
    provider: str | None = None
    model: str | None = None


@dataclass(slots=True)
class SecurityAssistantRuntime:
    timeout_seconds: float = 12.0
    turn_deadline_seconds: float = 15.0
    max_retries: int = 1
    budget: TurnBudget = field(default_factory=TurnBudget)
    metrics: list[InvocationMetric] = field(default_factory=list)
    turn_started_at: float = field(default_factory=perf_counter)
    execution_context: TurnExecutionContext | None = None

    def __post_init__(self) -> None:
        if self.execution_context is None:
            self.execution_context = TurnExecutionContext(
                deadline_seconds=self.turn_deadline_seconds,
                ai_budget=self.budget,
                started_at=self.turn_started_at,
            )
            return
        self.budget = self.execution_context.ai_budget

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
            ai_remaining_seconds = self.turn_deadline_seconds - (perf_counter() - self.turn_started_at)
            execution_remaining_seconds = (
                self.execution_context.remaining_seconds if self.execution_context is not None else ai_remaining_seconds
            )
            remaining_seconds = min(ai_remaining_seconds, execution_remaining_seconds)
            if remaining_seconds <= 0:
                self._metric(operation, 0, "turn_deadline_exceeded", error="turn_deadline_exceeded")
                return RuntimeResult(None, "fallback", "turn_deadline_exceeded")
            try:
                # Retries are provider calls too and consume the same per-turn
                # budget. A synthesis is intentionally never called twice.
                self.budget.reserve(operation)
            except BudgetExceededError as exc:
                self._metric(operation, 0, "budget_exceeded", error=str(exc))
                return RuntimeResult(None, "fallback", str(exc))
            started = perf_counter()
            call_timeout = min(self.timeout_seconds, remaining_seconds)
            deadline_limited = remaining_seconds <= self.timeout_seconds
            try:
                response = await asyncio.wait_for(call(), timeout=call_timeout)
                parsed = ModelResponse[output_type].model_validate(response)
                output = output_type.model_validate(parsed.output)
                self.budget.input_tokens += parsed.usage.input_tokens
                self.budget.output_tokens += parsed.usage.output_tokens
                self.budget.cost_usd += parsed.usage.cost_usd
                self._metric(operation, started, "ok", parsed)
                return RuntimeResult(
                    output,
                    "ok",
                    provider=parsed.provider,
                    model=parsed.model,
                )
            except TimeoutError:
                error = "turn_deadline_exceeded" if deadline_limited else "timeout"
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
