all: test
.PHONY: all

test:
	@cargo build --quiet
ifeq ($(shell uname),Darwin)
	@$(MAKE) -s -C testing/darwin-arm64 test
	@$(MAKE) -s -C testing/dyload test
else ifeq ($(shell uname),Linux)
	@$(MAKE) -s -C testing/linux test
	@$(MAKE) -s -C testing/linux-x86 test
endif
	@$(MAKE) -s -C testing/abi test
	@$(MAKE) -s -C testing/libc test
	@$(MAKE) -s -C testing/rust test
.PHONY: test
