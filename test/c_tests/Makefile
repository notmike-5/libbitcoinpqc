CC := gcc
CFLAGS := -Wall -Wextra -g
INCLUDE := -I../../include
LDFLAGS := -L../../target/debug/build/libbitcoinpqc-*/out/lib
LDLIBS := -lbitcoinpqc

.PHONY: all clean

all: ml_dsa_test

ml_dsa_test: ml_dsa_test.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f ml_dsa_test
