REGION=us-east-1


UV := $(shell command -v uv 2> /dev/null)

setup:
ifndef UV
	$(error "uv is not available, please install from https://docs.astral.sh/uv/getting-started/installation/")
endif
	uv sync --all-extras

test:
	uv sync --all-extras
	uv run pytest tests/

prod: setup
	uv run stacker build --region ${REGION} ${ARGS} conf/prod.env stacker.yaml

dev: setup
	uv run stacker build --region ${REGION} ${ARGS} conf/dev.env stacker.yaml

destroy-dev: setup
	uv run stacker destroy --region ${REGION} ${ARGS} conf/dev.env stacker.yaml

destroy-prod: setup
	uv run stacker destroy --region ${REGION} ${ARGS} conf/prod.env stacker.yaml
