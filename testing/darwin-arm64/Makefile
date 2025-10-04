TESTS += exit
TESTS += branch-b
TESTS += branch-bl
TESTS += branch-br
TESTS += branch-cond
TESTS += main
TESTS += printf
TESTS += loop
TESTS += random
TESTS += time

ASFLAGS =
LDFLAGS =

all: $(TESTS)

%: %.s
	gcc $(ASFLAGS) $< $(LDFLAGS) -o $@

%: %.S
	gcc $(ASFLAGS) $< $(LDFLAGS) -o $@

%: %.c
	gcc $(ASFLAGS) $< $(LDFLAGS) -o $@

test: $(TESTS)
	@for test in $(TESTS); do \
		echo "RUN $$test"; \
		../../target/debug/weave -- ./$$test || exit 1; \
	done

# Clean build artifacts
clean:
	rm -f $(TESTS)

.PHONY: all test clean
