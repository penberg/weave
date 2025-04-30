TESTS += hello

all: $(TESTS)

%: %.rs
	@rustc $< -o $@ 2>/dev/null

test: $(TESTS)
	@for test in $(TESTS); do \
		src=""; \
		if [ -f "$$test.rs" ]; then src="$$test.rs"; \
		fi; \
		../run-test.sh "$$test" "$$src" "rust" || exit 1; \
	done

clean:
	rm -f $(TESTS)

.PHONY: all test clean
