deps:
	uv sync --all-extras

lint:
	@uv run prek run --all-files
