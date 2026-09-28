.PHONY: check test clippy coverage ci
check:
	cargo check --all-targets

test:
	cargo test --all-targets

clippy:
	cargo clippy --all-targets -- -D warnings

coverage:
	./scripts/coverage

ci:
	./scripts/test-all
