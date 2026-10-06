TARGET:=linux-glibc-$(shell uname -m)

BIN:=sfinx

FIND:=$(shell command -v gfind find)

WATCH?=
WATCH+=$(shell $(FIND) src -type f -name '*.c')
WATCH+=$(shell $(FIND) src -type f -name '*.h')

.PHONY: default
default: build/${TARGET}/${BIN}

build/${TARGET}/${BIN}: build/${TARGET} $(WATCH)
	cd build/${TARGET} && dep install
	$(MAKE) --directory build/${TARGET} TARGET=${TARGET}

build/${TARGET}: $(WATCH)
	mkdir -p build/${TARGET}
	cp -rT src/              build/${TARGET}/src
	cp -rT target/common/    build/${TARGET}
	cp -rT target/${TARGET}/ build/${TARGET}

.PHONY: targets
targets:
	@ls -1 target | grep -v '^common$$'

.PHONY: clean
clean:
	rm -rf build

# Never let the catch-all try to rebuild the makefiles themselves
Makefile: ;

# Forward any other goal verbatim into the assembled target tree
.PHONY: FORCE
FORCE:
%: build/${TARGET} FORCE
	cd build/${TARGET} && dep install
	$(MAKE) --directory build/${TARGET} TARGET=${TARGET} $@
