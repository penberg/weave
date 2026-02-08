TESTS += main
TESTS += printf
TESTS += loop
TESTS += random
TESTS += time
TESTS += qsort
TESTS += math
#TESTS += pthreads

ASFLAGS = -fPIE
LDFLAGS = -pie
CFLAGS = -fPIE

all: $(TESTS)

%: %.s
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.S
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.c
	@gcc $(CFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

math: math.c
	@gcc $(CFLAGS) $< $(LDFLAGS) -lm -o $@

test: $(TESTS)
	@for test in $(TESTS); do \
		src=""; \
		if [ -f "$$test.c" ]; then src="$$test.c"; \
		elif [ -f "$$test.S" ]; then src="$$test.S"; \
		elif [ -f "$$test.s" ]; then src="$$test.s"; \
		fi; \
		../run-test.sh "$$test" "$$src" "libc" || exit 1; \
	done

# Clean build artifacts
clean:
	rm -f $(TESTS)

.PHONY: all test clean
