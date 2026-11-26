# The C API check: builds the shared library and runs a C program against
# include/nfse.h. `cargo test` covers the behaviour; this covers the header.
CC ?= cc
TARGET ?= target/debug

.PHONY: c-test
c-test:
	cargo build --lib
	$(CC) -Wall -Wextra -Werror -std=c11 -Iinclude tests/c/smoke.c -L$(TARGET) -lnfse -o $(TARGET)/c-smoke
	LD_LIBRARY_PATH=$(TARGET) DYLD_LIBRARY_PATH=$(TARGET) $(TARGET)/c-smoke
