TESTS += exit
TESTS += branch-direct
TESTS += branch-call
TESTS += branch-indirect
TESTS += branch-cond
TESTS += branch-test
TESTS += branch-pac

ASFLAGS =
LDFLAGS =

all: $(TESTS)

%: %.s
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.S
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.c
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

test: $(TESTS)
	@for test in $(TESTS); do \
		src=""; \
		if [ -f "$$test.c" ]; then src="$$test.c"; \
		elif [ -f "$$test.S" ]; then src="$$test.S"; \
		elif [ -f "$$test.s" ]; then src="$$test.s"; \
		fi; \
		../run-test.sh "$$test" "$$src" "darwin-arm64" || exit 1; \
	done

# Clean build artifacts
clean:
	rm -f $(TESTS)

.PHONY: all test clean
