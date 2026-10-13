CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I.. -I../src -I../lib/.dep/include
CFLAGS += -pthread

ifneq ($(SFINX_VERSION),)
CFLAGS += -DSFINX_VERSION='"$(SFINX_VERSION)"'
endif

include ../lib/.dep/config.mk

OUT := ../build/test
SRCS := $(filter-out _tap.c bench.c bench-chain.c,$(wildcard *.c))
TESTS := $(patsubst %.c,%,$(SRCS))
BINS := $(addprefix $(OUT)/,$(TESTS))
SH := $(filter-out _tap.sh,$(wildcard *.sh))

KECCAK := ../lib/finwo/keccak-fast/src
HASH := $(KECCAK)/keccak-fast.c $(wildcard $(KECCAK)/backend/*.c)
LIB := ../src/keypair.c $(wildcard ../src/fmt/*.c)

.PHONY: all
all: $(BINS)

../lib/.dep/config.mk:
	@cd .. && dep install

$(OUT):
	@mkdir -p $(OUT)

$(OUT)/09-ref: 09-ref.c ref/sfinx_ref.c ../src/sfinx.c _tap.c $(LIB) $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) $(HASH) -o $@

$(OUT)/10-batch: CFLAGS += -Wno-unused-function
$(OUT)/10-batch: 10-batch.c ref/sfinx_ref.c ../src/sfinx.c _tap.c $(LIB) $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) $(HASH) -o $@

$(OUT)/%: %.c ../src/sfinx.c _tap.c $(LIB) $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) $(HASH) -o $@

$(OUT)/bench: bench.c ../src/sfinx.c $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) bench.c ../src/sfinx.c $(HASH) -o $@

$(OUT)/bench-seq: CFLAGS := $(filter-out -pthread,$(CFLAGS))
$(OUT)/bench-seq: bench.c ../src/sfinx.c $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) bench.c ../src/sfinx.c $(HASH) -o $@

$(OUT)/bench-chain: CFLAGS += -I$(KECCAK)
$(OUT)/bench-chain: bench-chain.c ../src/sfinx.c $(LIB) $(HASH) | $(OUT)
	@$(CC) $(CFLAGS) bench-chain.c $(LIB) $(HASH) -o $@

.PHONY: bench
bench: $(OUT)/bench $(OUT)/bench-seq
	@$(OUT)/bench $(BENCH_ARGS)
	@$(OUT)/bench-seq $(BENCH_ARGS)

.PHONY: bench-chain
bench-chain: $(OUT)/bench-chain
	@$(OUT)/bench-chain $(BENCH_ARGS)

.PHONY: run
run: all
	@rc=0; \
	for t in $(BINS); do \
		echo "# $$t"; \
		$$t || rc=1; \
	done; \
	for t in $(SH); do \
		echo "# test/$$t"; \
		sh $$t || rc=1; \
	done; \
	exit $$rc

.PHONY: clean
clean:
	rm -rf $(OUT)
