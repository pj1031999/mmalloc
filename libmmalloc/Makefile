TOPDIR		:= $(realpath ..)
include $(TOPDIR)/build.mk

CFLAGS		+= -fPIC
LDFLAGS		+= -shared

SRCS		:= mmalloc.c
OBJS		:= $(subst .c,.o,$(SRCS))
DEPS		:= $(subst .o,.d,$(OBJS))

libmmalloc.so: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	$(RM) $(OBJS) $(DEPS) libmmalloc.so

-include $(DEPS)

# vim: tabstop=8 shiftwidth=8 noexpandtab:
