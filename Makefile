all: test
.PHONY: all

test:
	cargo build
	$(MAKE) -C testing/darwin-arm64 test
.PHONY: test
