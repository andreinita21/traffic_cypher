# Benchmark Makefile

CC      = cc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -I ../traffic_cypher_in_C/include

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib -framework Security
endif

LDFLAGS += -lssl -lcrypto -lpthread -lm

C_SRC_DIR = ../traffic_cypher_in_C/src_c
C_SOURCES = $(C_SRC_DIR)/hex_utils.c \
            $(C_SRC_DIR)/base64_utils.c \
            $(C_SRC_DIR)/uuid_gen.c \
            $(C_SRC_DIR)/crypto_derivation.c \
            $(C_SRC_DIR)/entropy_extractor.c \
            $(C_SRC_DIR)/entropy_pool.c \
            $(C_SRC_DIR)/frame_sampler.c \
            $(C_SRC_DIR)/stream_ingestion.c \
            $(C_SRC_DIR)/system_entropy_mixer.c \
            $(C_SRC_DIR)/password_gen.c \
            $(C_SRC_DIR)/totp.c \
            $(C_SRC_DIR)/vault.c \
            $(C_SRC_DIR)/key_rotation.c \
            $(C_SRC_DIR)/web_server.c

C_OBJECTS = $(C_SOURCES:.c=.bench.o)

.PHONY: all clean bench-c

all: bench_c

# Build C objects with .bench.o suffix to avoid conflicts
$(C_SRC_DIR)/%.bench.o: $(C_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

bench_c: bench_c.o $(C_OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

bench_c.o: bench_c.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f bench_c bench_c.o $(C_OBJECTS)
