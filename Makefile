# winmem 2 makefile

MAIN_FILE = tests/test.c

CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Iinclude -Isrc
LDFLAGS =
OUT = build/winmem.exe
LIB_SRC = $(wildcard src/*.c)
SRC = $(LIB_SRC) $(MAIN_FILE)
OBJ = $(patsubst %.c, build/%.o, $(SRC))

ifdef DEBUG
	CFLAGS += -DWM__DEBUG -g
endif

all: $(OUT)

$(OUT): $(OBJ)
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/%.o: %.c
	@if not exist "$(dir $@)" mkdir "$(dir $@)"
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@if exist build rmdir /s /q build

rebuild: clean all

.PHONY: all clean rebuild
