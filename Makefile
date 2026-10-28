.PHONY: setup format check package

setup:
	cargo fetch --locked

format:
	cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features -- -D warnings
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings
	cargo test --locked --all-targets --all-features
	cargo test --locked --doc --all-features
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
	$(MAKE) package

package:
	cargo package --locked --allow-dirty
