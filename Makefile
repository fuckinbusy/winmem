# winmem 2 makefile
CC                 = gcc
CFLAGS             = -std=c11 -Wall -Wextra -Iinclude -Isrc
LDFLAGS            =
STATIC_OUT         = build/lib/libwinmem_static.a
DYNAMIC_OUT        = build/bin/winmem.dll
DYNAMIC_OUT_IMPLIB = build/lib/libwinmem.dll.a
LIB_SRC            = $(wildcard src/*.c)
LIB_OBJ            = $(patsubst %.c, build/%.o, $(LIB_SRC))

ifdef DEBUG
	CFLAGS += -DWM__DEBUG -g
else
	CFLAGS += -O2 -Os
endif

all: $(STATIC_OUT) $(DYNAMIC_OUT)

static: $(STATIC_OUT)

dynamic: CFLAGS += -DWM__BUILD_DLL
dynamic: $(DYNAMIC_OUT)

$(STATIC_OUT): $(LIB_OBJ)
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	ar rcs $@ $^

$(DYNAMIC_OUT): $(LIB_OBJ)
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	$(CC) -shared $^ -o $@ -Wl,--out-implib,$(DYNAMIC_OUT_IMPLIB) $(LDFLAGS)

build/%.o: %.c
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@if exist build rmdir /s /q build

rebuild: clean all

.PHONY: all clean rebuild static dynamic
