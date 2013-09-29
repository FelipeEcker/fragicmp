# Makefile
CC		= gcc
FLAG	= -O3 -Wall -Werror

fragicmp: src/fragicmp.c
	$(CC) $(FLAG) -o fragicmp src/fragicmp.c

clean:
	rm -rf fragicmp

