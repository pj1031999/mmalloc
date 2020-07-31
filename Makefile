TOPDIR := $(realpath .)

.PHONY: all
all: libmmalloc tests

.PHONY: libmmalloc
libmmalloc: libmmalloc/libmmalloc.so

.PHONY: tests
tests: tests/tests

libmmalloc/libmmalloc.so:
	$(MAKE) -C libmmalloc libmmalloc.so

tests/tests: libmmalloc/libmmalloc.so
	$(MAKE) -C tests tests

.PHONY: clean
clean:
	$(MAKE) -C libmmalloc clean
	$(MAKE) -C tests clean

-include $(DEPS)

# vim: tabstop=8 shiftwidth=8 noexpandtab:
