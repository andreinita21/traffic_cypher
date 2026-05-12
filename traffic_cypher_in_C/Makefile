# Traffic Cypher — C rebuild
# Requires: OpenSSL (brew install openssl on macOS)

CC      = cc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -I include \
          -D_FORTIFY_SOURCE=2 -Wformat-security

# -Wstringop-truncation is GCC-only (clang on macOS doesn't recognise it and
# emits an "unknown warning option" warning, which would otherwise clutter
# every build). Enable it only when the compiler is GCC.
CC_IS_GCC := $(shell $(CC) --version 2>/dev/null | head -n 1 | grep -ci '^gcc' || true)
ifeq ($(CC_IS_GCC),1)
  CFLAGS += -Wstringop-truncation
endif

# Platform-specific knobs.
#
# On Linux/glibc, -std=c11 hides POSIX symbols (clock_gettime, fdopen, fileno,
# kill, ...) and GNU extensions (strcasestr) behind feature-test macros.
# -D_GNU_SOURCE exposes both groups. macOS' libc exposes everything by default,
# and defining _POSIX_C_SOURCE there would *hide* strcasestr — so the macro is
# Linux-only.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -framework Security
endif
ifeq ($(UNAME_S),Linux)
  CFLAGS += -D_GNU_SOURCE
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
          $(SRC_DIR)/key_rotation.c \
          $(SRC_DIR)/web_server.c

OBJECTS = $(SOURCES:.c=.o)

# Targets
.PHONY: all clean frontend

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
