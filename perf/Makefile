BPF_CLANG ?= clang
CC ?= gcc
ARCH ?= $(shell uname -m)

BPF_CFLAGS ?= -O2 -g -Wall -Wextra -target bpf -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS ?= -O2 -g -Wall -Wextra
USER_LIBS ?= -lbpf -lelf -lz

all: perf.bpf.o perf_user

perf.bpf.o: perf.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

perf_user: perf_user.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

run: perf_user
	./perf_user

clean:
	rm -f perf.bpf.o perf_user

.PHONY: all clean