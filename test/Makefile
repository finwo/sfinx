CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I.. -I../lib/.dep/include

OUT := ../build/test
SRCS := $(filter-out _tap.c,$(wildcard *.c))
TESTS := $(patsubst %.c,%,$(SRCS))
BINS := $(addprefix $(OUT)/,$(TESTS))

KECCAK := ../lib/coruus/keccak-tiny/keccak-tiny.c

.PHONY: all
all: $(BINS)

$(OUT):
	@mkdir -p $(OUT)

$(KECCAK):
	@cd .. && dep install

$(OUT)/%: %.c ../src/sfinx.c _tap.c $(KECCAK) | $(OUT)
	@$(CC) $(CFLAGS) $< $(KECCAK) -o $@

.PHONY: run
run: all
	@rc=0; \
	for t in $(BINS); do \
		echo "# $$t"; \
		$$t || rc=1; \
	done; \
	exit $$rc

.PHONY: clean
clean:
	rm -rf $(OUT)
