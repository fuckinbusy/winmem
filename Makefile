CC = gcc
NAME = winmem

lib:
	@echo Building (lib).
	@$(CC) -c -O3 -m64 -Wall -Wextra -o winmem.o -Iincludes src/winmem.c
	@ar rcs bin/libwinmem_static.lib winmem.o
	@del winmem.o
	@echo Success (lib).

dll:
	@echo Building (dll).
	@$(CC) -O3 -m64 -Wall -Wextra -shared -o bin/wm64.dll -Iincludes src/winmem.c -Wl,--out-implib,bin/libwm64.lib
	@echo Building finished.
	@echo Success (dll).

dllmain:
	@echo Building binary (main.c by dll).
	@mingw32-make dll
	@$(CC) -m64 -O3 -Wall -Wextra -Iincludes -o winmem.exe src/main.c -Lbin -lwm64
	@echo Building finished.

libmain:
	@echo Building binary (main.c by lib).
	@mingw32-make lib
	@$(CC) -m64 -O3 -Wall -Wextra -Iincludes -o winmem.exe src/main.c -Lbin -lwinmem_static
	@echo Building finished.