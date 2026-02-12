CC ?= gcc
CFLAGS = -O2 -Wall -Wextra

../tlcr_testapp: main.c
	$(CC) $(CFLAGS) -static -o $@ $<

clean:
	rm -f ../tlcr_testapp

.PHONY: clean
