TESTS += varargs
TESTS += struct_args
TESTS += float_args
TESTS += many_args
TESTS += callee_saved
TESTS += setjmp_test
TESTS += callback
TESTS += tail_call
TESTS += stack_align
TESTS += switch
TESTS += loops
TESTS += bitwise
TESTS += int_fp_mixed
TESTS += register_pressure
TESTS += string_ops
TESTS += recursion_deep
TESTS += complex_control

ASFLAGS = -fPIE
LDFLAGS = -pie
CFLAGS = -fPIE -O2 -fno-stack-protector

all: $(TESTS)

%: %.s
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.S
	@gcc $(ASFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

%: %.c
	@gcc $(CFLAGS) $< $(LDFLAGS) -o $@ 2>/dev/null

test: $(TESTS)
	@for test in $(TESTS); do \
		src=""; \
		if [ -f "$$test.c" ]; then src="$$test.c"; \
		elif [ -f "$$test.S" ]; then src="$$test.S"; \
		elif [ -f "$$test.s" ]; then src="$$test.s"; \
		fi; \
		../run-test.sh "$$test" "$$src" "abi" || exit 1; \
	done

clean:
	rm -f $(TESTS)

.PHONY: all test clean
