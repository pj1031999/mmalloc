TOPDIR		:= $(realpath ..)
include $(TOPDIR)/build.mk

CPPFLAGS 	+= -I../libmmalloc

SRCS		:= tests.c
OBJS		:= $(subst .c,.o,$(SRCS))
DEPS		:= $(subst .o,.d,$(OBJS))

tests: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(TOPDIR)/libmmalloc/libmmalloc.so

.PHONY: clean
clean:
	$(RM) $(OBJS) $(DEPS) tests

-include $(DEPS)

# vim: tabstop=8 shiftwidth=8 noexpandtab:
