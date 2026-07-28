CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -D_GNU_SOURCE
LDFLAGS ?=

SRC_DIR := src
OBJ_DIR := build

COMMON_SRC := $(SRC_DIR)/common.c $(SRC_DIR)/checksum.c $(SRC_DIR)/rawsock.c $(SRC_DIR)/session.c
COMMON_OBJ := $(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BIN := udpmimic

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ_DIR)/main.o $(OBJ_DIR)/server.o $(OBJ_DIR)/client.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN)
