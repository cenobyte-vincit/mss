# mss - macOS Security Scanner

PROG = mss
SRCS = mss.c scan.c macho.c plist.c

TEST_BUILD_DIR = tests/build
TEST_UNIT_BINS = \
	$(TEST_BUILD_DIR)/unit/test_macho \
	$(TEST_BUILD_DIR)/unit/test_plist \
	$(TEST_BUILD_DIR)/unit/test_scan

CPPCHECK ?= cppcheck
CFLAGS ?= -std=c17 -Wall -Wextra -Werror -pedantic -I.
LDFLAGS ?=

.PHONY: all clean test test-unit test-functional check lint \
	fixtures check-cppcheck

all: $(PROG) check-cppcheck

$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(TEST_BUILD_DIR)/unit $(TEST_BUILD_DIR)/fixtures:
	@mkdir -p $@

fixtures: $(TEST_BUILD_DIR)/fixtures
	@./tests/fixtures/build_fixtures.sh

$(TEST_BUILD_DIR)/unit/test_macho: tests/unit/test_macho.c macho.c plist.c \
		| $(TEST_BUILD_DIR)/unit
	$(CC) $(CFLAGS) -o $@ tests/unit/test_macho.c macho.c plist.c $(LDFLAGS)

$(TEST_BUILD_DIR)/unit/test_plist: tests/unit/test_plist.c plist.c \
		| $(TEST_BUILD_DIR)/unit
	$(CC) $(CFLAGS) -o $@ tests/unit/test_plist.c plist.c $(LDFLAGS)

$(TEST_BUILD_DIR)/unit/test_scan: tests/unit/test_scan.c scan.c macho.c plist.c \
		| $(TEST_BUILD_DIR)/unit
	$(CC) $(CFLAGS) -o $@ tests/unit/test_scan.c scan.c macho.c plist.c $(LDFLAGS)

test-unit: $(TEST_UNIT_BINS) fixtures
	@for t in $(TEST_UNIT_BINS); do \
		echo "==> $$t"; \
		./$$t || exit 1; \
	done

test-functional: $(PROG) fixtures
	@./tests/functional/run_tests.sh ./$(PROG)

test: test-unit test-functional

check-cppcheck:
	@command -v $(CPPCHECK) >/dev/null 2>&1 || { \
		echo "cppcheck not found — install it (see README)" >&2; exit 1; }
	$(CPPCHECK) --enable=warning,performance,portability \
		--error-exitcode=1 -I. $(SRCS) tests/unit/test_macho.c \
		tests/unit/test_plist.c tests/unit/test_scan.c

lint: check-cppcheck
check: lint

clean:
	rm -f $(PROG)
	rm -rf $(TEST_BUILD_DIR)