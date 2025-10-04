all: test
.PHONY: all

test:
	cargo build
ifeq ($(shell uname),Darwin)
	$(MAKE) -C testing/darwin-arm64 test
else ifeq ($(shell uname),Linux)
	$(MAKE) -C testing/linux-x86 test
endif
.PHONY: test
