ARCH = $(shell gcc -dumpmachine)
ALL_CFLAGS = -fPIC -fno-strict-aliasing -W -Wall -Wextra -Wformat -Wno-uninitialized -pipe -g -O2 -DARCH=\"$(ARCH)\" -pthread ${CFLAGS}
TARGET = fsp-trace

all:	$(TARGET)

$(TARGET): fsp-trace.c copyright.c adal_common.c adal_trace.c adal_parse.c
	$(CC) $^ $(ALL_CFLAGS) -o $@

clean distclean:
	$(RM) $(TARGET)
