CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I..

OUT := ../build/test
SRCS := $(filter-out _tap.c,$(wildcard *.c))
TESTS := $(patsubst %.c,%,$(SRCS))
BINS := $(addprefix $(OUT)/,$(TESTS))

.PHONY: all
all: $(BINS)

$(OUT):
	@mkdir -p $(OUT)

$(OUT)/%: %.c ../src/sfinx.c _tap.c | $(OUT)
	@$(CC) $(CFLAGS) $< -o $@

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
