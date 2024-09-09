CC := gcc

SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
BIN_DIR := bin

CFLAGS := -I$(INCLUDE_DIR)
LDFLAGS :=

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGET := slinjector

.PHONY: dirs clean libs


all: dirs $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN_DIR)/$@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

libs:
	@echo "Building libraries..."
	cd example_libs && ./build.sh

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(BIN_DIR)