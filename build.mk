CC	:= gcc

CPPFLAGS	:= -MMD -Wall -Wextra -Werror -DNDEBUG
CFLAGS		:= -std=gnu18 -march=native -O3 -fomit-frame-pointer -pipe
LDFLAGS		:= -Wl,-O3 -Wl,--as-needed -s
