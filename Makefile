test: clippy
	 RUST_BACKTRACE=full cargo test -- --nocapture
clippy:
	cargo clippy
