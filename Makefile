# options
ignore_output = &> /dev/null

.PHONY: run-dev test build docker

run-dev:
	@cargo run

test:
	@cargo test --workspace -- --nocapture

test-all:
	@cargo test --workspace -- --nocapture --include-ignored

lint:
	@cargo clippy --all-targets --all-features --workspace --tests

fix:
	@cargo clippy --fix --workspace --tests
