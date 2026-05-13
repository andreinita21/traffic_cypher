# Traffic Cypher — C rebuild
# Requires: OpenSSL 3.2+ (Argon2id via EVP_KDF_fetch("ARGON2ID")). Older
# OpenSSL (3.0/3.1) cannot supply Argon2id and will fail the
# OPENSSL_VERSION_NUMBER check at the top of src_c/vault.c. macOS Homebrew
# `openssl@3` is 3.3+ and works out of the box. On Linux, ensure
# `pkg-config --modversion openssl` reports at least 3.2.0.

CC      = cc
# Compile-time hardening flags (REMEDIATION_PLAN.md "What does not fit in this
# plan" — partial coverage was added with the #3 str_buf migration; this is
# the full set).
#   -D_FORTIFY_SOURCE=2     glibc runtime overflow checks on str/mem fns
#   -Wformat-security       refuse non-literal printf formats
#   -fstack-protector-strong canaries on functions with local arrays/refs
#   -fPIE                   compile position-independent; pairs with -pie below
CFLAGS  = -Wall -Wextra -O2 -std=c11 -I include \
          -D_FORTIFY_SOURCE=2 -Wformat-security \
          -fstack-protector-strong -fPIE

# -Wstringop-truncation and -Wstringop-overflow are GCC-only (clang on macOS
# emits an "unknown warning option" diagnostic). Enable them only under GCC.
CC_IS_GCC := $(shell $(CC) --version 2>/dev/null | head -n 1 | grep -ci '^gcc' || true)
ifeq ($(CC_IS_GCC),1)
  CFLAGS += -Wstringop-truncation -Wstringop-overflow=4
endif

# Platform-specific knobs.
#
# On Linux/glibc, -std=c11 hides POSIX symbols (clock_gettime, fdopen, fileno,
# kill, ...) and GNU extensions (strcasestr) behind feature-test macros.
# -D_GNU_SOURCE exposes both groups. macOS' libc exposes everything by default,
# and defining _POSIX_C_SOURCE there would *hide* strcasestr — so the macro is
# Linux-only.
#
# OPENSSL_PREFIX honored on both OSes. Required on Linux when the distro ships
# OpenSSL < 3.2 (Ubuntu 24.04 has 3.0); CI builds OpenSSL 3.3 to /usr/local/openssl-3.3
# and sets OPENSSL_PREFIX accordingly.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  # macOS clang produces PIE executables by default; -Wl,-pie is implicit.
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -framework Security
endif
ifeq ($(UNAME_S),Linux)
  CFLAGS += -D_GNU_SOURCE
  # Linker hardening on Linux/GNU ld: PIE, full RELRO, non-executable stack.
  # These flags are silently ignored by lld; rejected by ld64 (hence macOS-only
  # split above).
  LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
  ifdef OPENSSL_PREFIX
    CFLAGS  += -I$(OPENSSL_PREFIX)/include
    LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib
  endif
endif

LDFLAGS += -lssl -lcrypto -lpthread -lm

SRC_DIR = src_c
SOURCES = $(SRC_DIR)/str_buf.c \
          $(SRC_DIR)/hex_utils.c \
          $(SRC_DIR)/base64_utils.c \
          $(SRC_DIR)/uuid_gen.c \
          $(SRC_DIR)/crypto_derivation.c \
          $(SRC_DIR)/entropy_extractor.c \
          $(SRC_DIR)/entropy_pool.c \
          $(SRC_DIR)/frame_sampler.c \
          $(SRC_DIR)/stream_ingestion.c \
          $(SRC_DIR)/system_entropy_mixer.c \
          $(SRC_DIR)/password_gen.c \
          $(SRC_DIR)/totp.c \
          $(SRC_DIR)/vault.c \
          $(SRC_DIR)/multi_stream.c \
          $(SRC_DIR)/key_rotation.c \
          $(SRC_DIR)/web_server.c

OBJECTS = $(SOURCES:.c=.o)

# Targets
.PHONY: all clean frontend fuzz fuzz-clean msm_test msm_test-clean

all: traffic-cypher traffic-cypher-pm frontend

# Frontend lives canonically at repo root (../frontend/). The C web server
# reads frontend/index.html etc. at runtime relative to its CWD, so we mirror
# the tree into ./frontend/ at build time. See REMEDIATION_PLAN.md #5b.
frontend:
	rm -rf ./frontend
	cp -R ../frontend ./frontend

traffic-cypher: $(OBJECTS) $(SRC_DIR)/main.o
	$(CC) -o $@ $^ $(LDFLAGS)

traffic-cypher-pm: $(OBJECTS) $(SRC_DIR)/pm_main.o
	$(CC) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SRC_DIR)/*.o traffic-cypher traffic-cypher-pm
	rm -rf ./frontend

# ----------------------------------------------------------------------------
# Fuzz harness (REMEDIATION_PLAN.md Week 4+ #10d).
#
# Builds one libFuzzer binary per target in fuzz_c/fuzz_targets/. Always uses
# clang with -fsanitize=fuzzer,address; the regular `all` target is unaffected.
# Run on demand:
#
#   make -C traffic_cypher_in_C fuzz
#   traffic_cypher_in_C/fuzz_c/fuzz_hex_decode \
#       traffic_cypher_in_C/fuzz_c/corpus/hex_decode \
#       -max_total_time=60
#
# CI is not wired (requires clang + libFuzzer runtime on the runner). Rust
# fuzz scaffolding under traffic_cypher_in_Rust/fuzz/ follows the same
# "build on demand" pattern.
# ----------------------------------------------------------------------------
FUZZ_CC      ?= clang
FUZZ_DIR     := fuzz_c
FUZZ_OUT     := $(FUZZ_DIR)/fuzz_hex_decode \
                $(FUZZ_DIR)/fuzz_json_get_string \
                $(FUZZ_DIR)/fuzz_parse_vault_entries

# Sources we recompile into each fuzz binary with sanitizers. Kept minimal
# so iterations stay fast (avoid pulling in OpenSSL/web_server/etc).
FUZZ_CORE_SRC := $(SRC_DIR)/str_buf.c $(SRC_DIR)/hex_utils.c \
                 $(SRC_DIR)/base64_utils.c

# vault.c needs the wrapper API + a few helpers; we link it for the two
# JSON-targeting fuzzers. -DENABLE_FUZZ_API exposes the static-wrappers.
# OpenSSL is still required because vault.c references EVP_* in unrelated
# functions; the linker just keeps the symbols satisfied.
FUZZ_VAULT_SRC := $(FUZZ_CORE_SRC) $(SRC_DIR)/vault.c $(SRC_DIR)/uuid_gen.c \
                  $(SRC_DIR)/crypto_derivation.c

# Default sanitizer set is `fuzzer` only — combining `fuzzer,address` hangs
# libFuzzer init on macOS arm64 with Homebrew LLVM 20 (the ASan runtime
# dyld path stalls before main returns). Linux + clang doesn't have this
# bug, so CI can opt in:
#   make fuzz FUZZ_SANITIZER=fuzzer,address
FUZZ_SANITIZER ?= fuzzer

FUZZ_CFLAGS  := -O1 -g -std=c11 -I include -DENABLE_FUZZ_API \
                -fsanitize=$(FUZZ_SANITIZER) -fno-omit-frame-pointer
FUZZ_LDFLAGS := -fsanitize=$(FUZZ_SANITIZER)
ifeq ($(UNAME_S),Darwin)
  FUZZ_CFLAGS  += -I$(OPENSSL_PREFIX)/include
  # `-framework Security` is needed by uuid_gen.c (SecRandomCopyBytes).
  FUZZ_LDFLAGS += -L$(OPENSSL_PREFIX)/lib -framework Security
endif
ifeq ($(UNAME_S),Linux)
  FUZZ_CFLAGS += -D_GNU_SOURCE
  ifdef OPENSSL_PREFIX
    FUZZ_CFLAGS  += -I$(OPENSSL_PREFIX)/include
    FUZZ_LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib
  endif
endif
FUZZ_LIBS    := -lssl -lcrypto -lpthread -lm

fuzz: $(FUZZ_OUT)

$(FUZZ_DIR)/fuzz_hex_decode: $(FUZZ_DIR)/fuzz_targets/fuzz_hex_decode.c $(FUZZ_CORE_SRC)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ $(FUZZ_LDFLAGS)

$(FUZZ_DIR)/fuzz_json_get_string: $(FUZZ_DIR)/fuzz_targets/fuzz_json_get_string.c $(FUZZ_VAULT_SRC)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

$(FUZZ_DIR)/fuzz_parse_vault_entries: $(FUZZ_DIR)/fuzz_targets/fuzz_parse_vault_entries.c $(FUZZ_VAULT_SRC)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ $(FUZZ_LDFLAGS) $(FUZZ_LIBS)

fuzz-clean:
	rm -f $(FUZZ_OUT)
	rm -rf $(FUZZ_DIR)/*.dSYM

# ----------------------------------------------------------------------------
# multi_stream unit test (REMEDIATION_PLAN.md #1a stage 1).
#
# Standalone test binary that exercises msm_new / push / pick / get_statuses
# without going through ffmpeg or yt-dlp (the production environment may not
# have either installed — see REMEDIATION_PROGRESS.md environment check).
# Test-only seams (msm_test_push_frame, msm_test_register_slot) are gated by
# -DENABLE_MSM_TEST_API and never enter the production binary.
#
#   make -C traffic_cypher_in_C msm_test && ./traffic_cypher_in_C/msm_test
# ----------------------------------------------------------------------------
MSM_TEST_SRC := $(SRC_DIR)/multi_stream.c $(SRC_DIR)/stream_ingestion.c \
                $(SRC_DIR)/frame_sampler.c
MSM_TEST_CFLAGS := -O0 -g -std=c11 -I include -DENABLE_MSM_TEST_API \
                   -fstack-protector-strong
ifeq ($(UNAME_S),Linux)
  MSM_TEST_CFLAGS += -D_GNU_SOURCE
endif

msm_test: tests_c/msm_test.c $(MSM_TEST_SRC)
	$(CC) $(MSM_TEST_CFLAGS) -o $@ $^ -lpthread

msm_test-clean:
	rm -f msm_test
	rm -rf msm_test.dSYM
