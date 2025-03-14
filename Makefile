CC = gcc
NAME = winmem

libstatic:
	@echo Building binary (libstatic).
	@$(CC) -c -O3 -m64 -Wall -Wextra -o winmem.o -Iincludes src/winmem.c
	@ar rcs bin/libwinmem_static.lib winmem.o
	@del winmem.o
	@echo Building finished.

libshared:
	@echo Building binary (libshared).
	@$(CC) -O3 -m64 -Wall -Wextra -shared -o bin/wm64.dll -Iincludes src/winmem.c -Wl,--out-implib,bin/libwm64.lib
	@echo Building finished.

dllmain:
	@echo Building binary (main.c by dll).
	@$(CC) -m64 -O3 -Wall -Wextra -Iincludes -o winmem.exe src/main.c -Lbin -lwm64
	@echo Building finished.

libmain:
	@echo Building binary (main.c by lib).
	@$(CC) -m64 -O3 -Wall -Wextra -Iincludes -o winmem.exe src/main.c -Lbin -lwinmem_static
	@echo Building finished.