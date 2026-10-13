TARGET?=

BIN=sfinx

SRC:=
SRC+=$(wildcard src/*.c)
SRC+=$(wildcard src/*/*.c)
SRC+=$(wildcard src/*/*/*.c)

CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=

# Drop unreferenced code: dependencies export whole libraries, of which we use a part
CFLAGS +=-ffunction-sections -fdata-sections
ifeq ($(shell uname -s),Darwin)
LDFLAGS+=-Wl,-dead_strip
else
LDFLAGS+=-Wl,--gc-sections
endif

# pthread backs the optional worker pool in sfinx.c; the library manifest leaves it to the consumer
CFLAGS +=-pthread
LDFLAGS+=-pthread

ifneq ($(SFINX_VERSION),)
CFLAGS +=-DSFINX_VERSION='"$(SFINX_VERSION)"'
endif

INCLUDES:=
INCLUDES+=-I src

include lib/.dep/config.mk

# Target-specific overrides, optional.
# Supplied by target/<target>/Makefile.target
-include Makefile.target

CFLAGS+=$(INCLUDES)

OBJ:=$(SRC:.c=.o)

.PHONY: default
default: $(BIN)

lib/.dep/config.mk:
	@dep install

%.o: %.c $(LIBS)
	$(CC) $(CFLAGS) $(@:.o=.c) -D__NAME=\"$(BIN)\" -D__TARGET=\"$(TARGET)\" -c -o $@

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -f $(OBJ) $(BIN)

.PHONY: install
install: $(BIN)
	install -Dm0755 $(BIN) $(DESTDIR)/usr/bin/$(BIN)
