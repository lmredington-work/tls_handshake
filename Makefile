CPPFLAGS=
CFLAGS=-std=gnu11 -g -Wall -Wextra -O2
LDFLAGS=
LDLIBS=-lssl -lcrypto

PROG=time_handshake
OBJS=$(patsubst %.c,%.o,$(wildcard *.c))

.DUMMY: all
all: $(PROG)

%.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

$(PROG): $(OBJS)

.DUMMY:
clean:
	@$(RM) $(PROG) $(OBJS)
