CC = gcc
NAME = winmem

libstatic:
	@echo Building binary (libstatic).
	@$(CC) -c -O3 -m64 -Wall -Wextra -o winmem.o -Iincludes src/winmem.c
	@ar rcs libwinmem.lib winmem.o
	@del winmem.o
	@echo Building finished.

libshared:
	@echo Building binary (libshared).
	@$(CC) -c -O3 -m64 -Wall -Wextra -shared -o winmem.dll -Iincludes src/winmem.c
	@echo Building finished.