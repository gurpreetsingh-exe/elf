CC = gcc
CFLAGS = -Wall -Wextra

.PHONY: all
all:
	$(CC) src/elf.c -o elf $(CFLAGS)
