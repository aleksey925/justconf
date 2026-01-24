vault:
	docker compose exec -it vault /setup.sh

deps:
	uv sync --all-extras

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
