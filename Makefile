CC = gcc
NAME = winmem
ENABLE_LOGGING ?= 0
CFLAGS = -m64 -Wall -Wextra -Iincludes
RELEASE_CFLAGS = -O3
DEBUG_CFLAGS = -O0 -DENABLE_LOGGING=1
PYTHON_CFLAGS = -O0  # for Python DLL

LIB_DIR = lib
SRC = src/winmem.c

.PHONY: all release debug clean

all: release debug

start:
	@echo "Use: release | debug | clean"

release: CFLAGS += $(RELEASE_CFLAGS)
release: $(LIB_DIR)/libwinmem64.lib $(LIB_DIR)/winmem64.dll $(LIB_DIR)/pywinmem64.dll

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(LIB_DIR)/libwinmem64_log.lib $(LIB_DIR)/winmem64_log.dll $(LIB_DIR)/pywinmem64_log.dll

# Release static
$(LIB_DIR)/libwinmem64.lib: $(SRC)
	@echo Building $(@F)
	@$(CC) -c $(CFLAGS) -o winmem.o $<
	@ar rcs $@ winmem.o
	@del winmem.o
	@echo Finished $(@F)

# Release static
$(LIB_DIR)/libwinmem64_log.lib: $(SRC)
	@echo Building $(@F)
	@$(CC) -c $(CFLAGS) -o winmem.o $<
	@ar rcs $@ winmem.o
	@del winmem.o
	@echo Finished $(@F)

# Release DLL
$(LIB_DIR)/winmem64.dll: $(SRC)
	@echo Building $(@F)
	@$(CC) -shared $(CFLAGS) -o $@ $< -Wl,--out-implib,$(LIB_DIR)/libwm64.lib
	@if exist lib/libwm64.lib del lib\libwm64.lib
	@echo Finished $(@F)

# Debug DLL
$(LIB_DIR)/winmem64_log.dll: $(SRC)
	@echo Building $(@F)
	@$(CC) -shared $(CFLAGS) -o $@ $< -Wl,--out-implib,$(LIB_DIR)/libwm64_log.lib
	@if exist lib/libwm64_log.lib del lib\libwm64_log.lib
	@echo Finished $(@F)

# Release PyDLL
$(LIB_DIR)/pywinmem64.dll: $(SRC)
	@echo Building $(@F)
	@$(CC) -shared $(CFLAGS) $(PYTHON_CFLAGS) -o $@ $<
	@echo Finished $(@F)

# Debug PyDLL
$(LIB_DIR)/pywinmem64_log.dll: $(SRC)
	@echo Building $(@F)
	@$(CC) -shared $(CFLAGS) $(PYTHON_CFLAGS) -o $@ $<
	@echo Finished $(@F)

# Um...uuuh...yes
clean:
	@if exist $(LIB_DIR)\*.lib del /Q $(LIB_DIR)\*.lib
	@if exist $(LIB_DIR)\*.dll del /Q $(LIB_DIR)\*.dll
	@echo Cleaned everyting