UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    LIBEXT = dylib
    LIBFLAGS = -dynamiclib
else
    LIBEXT = so
    LIBFLAGS = -shared -fPIC
endif

all: libnondet.$(LIBEXT) dyload

libnondet.$(LIBEXT): libnondet.c
	@$(CC) $(LIBFLAGS) -o $@ $< 2>/dev/null

dyload: dyload.c
	@$(CC) -o $@ $< -ldl 2>/dev/null

clean:
	rm -f libnondet.$(LIBEXT) dyload

# Test that weave produces deterministic output from the dynamically loaded library.
test: all
	@../run-test.sh "dyload" "dyload.c" "dyload"

.PHONY: all clean test
