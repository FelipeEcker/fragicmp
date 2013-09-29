#####################################################*
#####################################################*
#*                Makefile  FRAGICMP.C               *
#*                   v0.2.0                          *
#*            Data: 10/03/2008 (17:15)               *
#*                                                   *
#*                                                   *
#*       .....................................       *
#*                                                   *
#*      Felipe Ecker (Khun) - khun@hexcodes.org      *
#*                                                   *
#*                                                   *
#####################################################*

CC = gcc
FLAG = -O2 -Wall -Werror
BIN	= ./bin/

fragicmp: fragicmp.c
	$(CC) $(FLAG) -o fragicmp fragicmp.c

clean:
	rm -rf fragicmp

