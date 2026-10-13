TARGET:=$(shell uname -s | tr '[:upper:]' '[:lower:]')-$(shell uname -m)

BIN:=sfinx

SFINX_VERSION?=0.3.0
export SFINX_VERSION

FIND:=$(shell command -v gfind find)

WATCH?=
WATCH+=$(shell $(FIND) src -type f -name '*.c')
WATCH+=$(shell $(FIND) src -type f -name '*.h')

.PHONY: default
default: build/${TARGET}/${BIN}

build/${TARGET}/${BIN}: build/${TARGET} $(WATCH)
	$(MAKE) --directory build/${TARGET} TARGET=${TARGET}

build/${TARGET}: $(WATCH)
	mkdir -p build/${TARGET}/src
	cp -R src/.              build/${TARGET}/src/
	cp -R target/common/.    build/${TARGET}/
	cp -R target/${TARGET}/. build/${TARGET}/

.PHONY: targets
targets:
	@ls -1 target | grep -v '^common$$'

.PHONY: clean
clean:
	rm -rf build

.PHONY: test
test:
	@$(MAKE) --no-print-directory --directory test run

.PHONY: bench
bench:
	@$(MAKE) --no-print-directory --directory test bench BENCH_ARGS="$(BENCH_ARGS)"

# Never let the catch-all try to rebuild the makefiles themselves
Makefile: ;

STDDOC?=stddoc

.PHONY: docs
docs: docs/api.md

docs/api.md: src/sfinx.h
	$(STDDOC) < src/sfinx.h > docs/api.md

.PHONY: format
format:
	$(FIND) src/ -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +
	$(FIND) test/ -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +

# Forward any other goal verbatim into the assembled target tree
.PHONY: FORCE
FORCE:
%: build/${TARGET} FORCE
	$(MAKE) --directory build/${TARGET} TARGET=${TARGET} $@
