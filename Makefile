CC = gcc
NAME = winmem

start:
	@echo "You should choose an option: lib | dll | lib_log | dll_log"

lib:
	@echo Building (lib).
	@$(CC) -c -O3 -m64 -Wall -Wextra -o winmem.o -Iincludes src/winmem.c
	@ar rcs lib/libwinmem64.lib winmem.o
	@del winmem.o
	@echo Finished (lib).

lib_log:
	@echo Building (lib with logging).
	@$(CC) -c -O3 -m64 -Wall -Wextra -o winmem.o -Iincludes src/winmem.c
	@ar rcs lib/libwinmem64_log.lib winmem.o
	@del winmem.o
	@echo Finished (lib).

dll:
	@echo Building (dll).
	@$(CC) -O3 -m64 -Wall -Wextra -shared -o lib/wm64.dll -Iincludes src/winmem.c -Wl,--out-implib,lib/libwm64.lib
	@if exist lib/libwm64.lib del lib\libwm64.lib
	@echo Finished (dll).

dll_log:
	@echo Building (dll lib with logging).
	@$(CC) -O3 -m64 -Wall -Wextra -shared -o lib/wm64_log.dll -Iincludes src/winmem.c -Wl,--out-implib,lib/libwm64_log.lib
	@if exist lib/libwm64_log.lib del lib\libwm64_log.lib
	@echo Finished (dll).