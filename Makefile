all: test
.PHONY: all

test:
	@cargo build --quiet
ifeq ($(shell uname),Darwin)
	@$(MAKE) -s -C testing/conformance/darwin-arm64 test
	@$(MAKE) -s -C testing/conformance/dyload test
else ifeq ($(shell uname),Linux)
	@$(MAKE) -s -C testing/conformance/linux test
	@$(MAKE) -s -C testing/conformance/linux-x86 test
endif
	@$(MAKE) -s -C testing/conformance/abi test
	@$(MAKE) -s -C testing/conformance/libc test
	@$(MAKE) -s -C testing/conformance/rust test
.PHONY: test
