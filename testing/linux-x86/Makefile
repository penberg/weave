TESTS += exit

ASFLAGS =
LDFLAGS = -nostdlib

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
