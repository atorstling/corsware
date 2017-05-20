test: clippy
	 RUST_BACKTRACE=full cargo test -- --nocapture
clippy:
	cargo clippy
update-doc:
	cargo doc
	rm -rf docs
	cp -r target/doc docs
