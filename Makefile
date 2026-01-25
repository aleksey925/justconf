vault:
	docker compose exec -it vault /setup.sh

deps:
ifdef group
	uv sync --group $(group)
else
	uv sync --all-groups
endif

test:
	uv run pytest --cov=justconf --cov-report=xml

test-int:
	uv run pytest -m integration

test-all:
	uv run pytest -m ''

lint:
	@uv run prek run --all-files

build:
	uv build

publish:
	uv publish

.PHONY: docs
docs:
	python scripts/gen_docs.py
	uv run mkdocs build --strict

.PHONY: docs-serve
docs-serve:
	python scripts/gen_docs.py
	uv run mkdocs serve
