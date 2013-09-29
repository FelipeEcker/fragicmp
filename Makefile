#################################################################################################*
#################################################################################################*
#*                                                                                               *
#*                                              MAKEFILE                                         *
#*                                    Compilation file de Fragicmp                               *
#*                                                                                               *
#*                                              -- ## --                                         *
#*	                                        Ver: 1.0                                    	 *
#*                            (Este arquivo Ã© parte da Ferramenta FragIcmp)                     *
#*                                       Data: 10/03/2008 (17:15)                                *
#*                                                                                               *
#*                                                                                               *
#*                       .......................................................                 *
#*                                                                                               *
#*                                Felipe de Oliveira - khun@hexcodes.org                         *
#*                                                                                               *
#*                                             			                                 *
#################################################################################################*

CC = gcc
FLAG = -O2 -Wall -Werror
BIN	= ./bin/

fragicmp: fragicmp.c
	$(CC) $(FLAG) -o fragicmp fragicmp.c

clean:
	rm -rf fragicmp


