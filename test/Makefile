CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I.. -I../src -I../lib/.dep/include

OUT := ../build/test
SRCS := $(filter-out _tap.c,$(wildcard *.c))
TESTS := $(patsubst %.c,%,$(SRCS))
BINS := $(addprefix $(OUT)/,$(TESTS))
SH := $(filter-out _tap.sh,$(wildcard *.sh))

KECCAK := ../lib/coruus/keccak-tiny/keccak-tiny.c
LIB := ../src/keypair.c $(wildcard ../src/fmt/*.c)

.PHONY: all
all: $(BINS)

$(OUT):
	@mkdir -p $(OUT)

$(KECCAK):
	@cd .. && dep install

$(OUT)/09-ref: 09-ref.c ref/sfinx_ref.c ../src/sfinx.c _tap.c $(LIB) $(KECCAK) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) $(KECCAK) -o $@

$(OUT)/%: %.c ../src/sfinx.c _tap.c $(LIB) $(KECCAK) | $(OUT)
	@$(CC) $(CFLAGS) $< $(LIB) $(KECCAK) -o $@

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
