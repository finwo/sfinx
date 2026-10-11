CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I.. -I../src -I../lib/.dep/include
CFLAGS += -pthread

OUT := ../build/test
SRCS := $(filter-out _tap.c bench.c,$(wildcard *.c))
TESTS := $(patsubst %.c,%,$(SRCS))
BINS := $(addprefix $(OUT)/,$(TESTS))
SH := $(filter-out _tap.sh,$(wildcard *.sh))

HASH := ../lib/finwo/keccak-fast/src/keccak-fast.c \
        $(wildcard ../lib/finwo/keccak-fast/src/backend/*.c)
LIB := ../src/keypair.c $(wildcard ../src/fmt/*.c)

.PHONY: all
all: $(BINS)

$(OUT):
	@mkdir -p $(OUT)

$(HASH):
	@cd .. && dep install

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

.PHONY: bench
bench: $(OUT)/bench $(OUT)/bench-seq
	@$(OUT)/bench $(BENCH_ARGS)
	@$(OUT)/bench-seq $(BENCH_ARGS)

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
