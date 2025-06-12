CC = gcc
NAME = winmem
ENABLE_LOGGING ?= 0

INCLUDES = -Iincludes
LOGGING_DEFINE = -DENABLE_LOGGING=$(ENABLE_LOGGING)

BASE_CFLAGS = -m64 -Wall -Wextra $(INCLUDES)
RELEASE_CFLAGS = -O3
DEBUG_CFLAGS = -O0 -DENABLE_LOGGING=1
DLL_FLAGS = -DWINMEM_DLL -DWINMEM_EXPORTS
PYTHON_FLAGS = -O2 -fPIC

LIB_DIR = lib
SRC = src/winmem.c
OBJ = winmem.o

.PHONY: all release debug clean

all: release debug

start:
	@echo "Use: make release | debug | clean"

# ==== Static Release ====
release: CFLAGS += $(RELEASE_CFLAGS)
release: $(LIB_DIR)/libwinmem64.lib $(LIB_DIR)/winmem64.dll $(LIB_DIR)/pywinmem64.dll

# ==== Static Debug ====
debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(LIB_DIR)/libwinmem64_log.lib $(LIB_DIR)/winmem64_log.dll $(LIB_DIR)/pywinmem64_log.dll

# ==== Ensure lib directory exists ====
$(LIB_DIR):
	@mkdir $(LIB_DIR)

# ==== Static Libraries ====
$(LIB_DIR)/libwinmem64.lib: $(SRC) | $(LIB_DIR)
	@echo [Static] Building $(@F)
	@$(CC) -c $(BASE_CFLAGS) $(CFLAGS) -o $(OBJ) $<
	@ar rcs $@ $(OBJ)
	@del $(OBJ)
	@echo Finished $(@F)

$(LIB_DIR)/libwinmem64_log.lib: $(SRC) | $(LIB_DIR)
	@echo [Static+Log] Building $(@F)
	@$(CC) -c $(BASE_CFLAGS) $(CFLAGS) -o $(OBJ) $<
	@ar rcs $@ $(OBJ)
	@del $(OBJ)
	@echo Finished $(@F)

# ==== DLLs ====
$(LIB_DIR)/winmem64.dll: $(SRC) | $(LIB_DIR)
	@echo [DLL] Building $(@F)
	@$(CC) -shared $(BASE_CFLAGS) $(RELEASE_CFLAGS) $(DLL_FLAGS) -o $@ $< -Wl,--out-implib,$(LIB_DIR)/libwm64.lib
	@if exist $(LIB_DIR)\libwm64.lib del $(LIB_DIR)\libwm64.lib
	@echo Finished $(@F)

$(LIB_DIR)/winmem64_log.dll: $(SRC) | $(LIB_DIR)
	@echo [DLL+Log] Building $(@F)
	@$(CC) -shared $(BASE_CFLAGS) $(DEBUG_CFLAGS) $(DLL_FLAGS) -o $@ $< -Wl,--out-implib,$(LIB_DIR)/libwm64_log.lib
	@if exist $(LIB_DIR)\libwm64_log.lib del $(LIB_DIR)\libwm64_log.lib
	@echo Finished $(@F)

# ==== Python DLLs ====
$(LIB_DIR)/pywinmem64.dll: $(SRC) | $(LIB_DIR)
	@echo [PyDLL] Building $(@F)
	@$(CC) -shared $(BASE_CFLAGS) $(PYTHON_FLAGS) $(DLL_FLAGS) -o $@ $<
	@echo Finished $(@F)

$(LIB_DIR)/pywinmem64_log.dll: $(SRC) | $(LIB_DIR)
	@echo [PyDLL+Log] Building $(@F)
	@$(CC) -shared $(BASE_CFLAGS) $(DEBUG_CFLAGS) $(PYTHON_FLAGS) $(DLL_FLAGS) -o $@ $<
	@echo Finished $(@F)

# ==== Clean ====
clean:
	@if exist $(LIB_DIR)\*.lib del /Q $(LIB_DIR)\*.lib
	@if exist $(LIB_DIR)\*.dll del /Q $(LIB_DIR)\*.dll
	@if exist *.o del /Q *.o
	@echo Cleaned everything.
