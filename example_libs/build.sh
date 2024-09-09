#!/usr/bin/env bash

# Define variables
CC=gcc
SRC_DIR=src
BIN_DIR=bin

# Rereate bin directory
rm -rf ${BIN_DIR}
mkdir -p ${BIN_DIR}

# Compile injectme_puts.c
${CC} -Wall -shared -fPIC -O2 -o ${BIN_DIR}/injectme_puts.so ${SRC_DIR}/injectme_puts.c

# Compile injectme_implant.c
${CC} -Wall -shared -fPIC -O2 -o ${BIN_DIR}/injectme_implant.so ${SRC_DIR}/injectme_implant.c

# Compile injectme_hook.c
${CC} -Iinclude -Wall -shared -fPIC -O2 -o ${BIN_DIR}/injectme_hook.so ${SRC_DIR}/injectme_hook.c ${SRC_DIR}/hooking.c
