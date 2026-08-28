.PHONY: run test lint format typecheck frontend-test frontend-lint frontend-typecheck frontend-cutover frontend-check check clean

run:
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/

frontend-test:
	npm --prefix frontend test

frontend-lint:
	npm --prefix frontend run lint

frontend-typecheck:
	npm --prefix frontend run typecheck

frontend-cutover:
	npm --prefix frontend run check:cutover

frontend-check: frontend-test frontend-lint frontend-typecheck frontend-cutover

check: lint test frontend-check

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +
