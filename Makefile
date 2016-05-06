MAIN = radius-test

CFLAGS = -Wall -Wextra -Werror -Wfatal-errors -pedantic -std=c99 -D_POSIX_C_SOURCE=201112
LDFLAGS = -lcyassl
OBJS = $(MAIN).o

.PHONY: clean

all: $(MAIN)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

radius-test: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(MAIN) *.o
