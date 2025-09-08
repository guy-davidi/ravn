# RAVN Security Platform Makefile
# Pure C implementation with daemon and CLI modes

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I$(SRC_DIR)
LDFLAGS = -lbpf -lhiredis -lpthread -lm

# Directories
SRC_DIR = src
BUILD_DIR = artifacts
ARTIFACTS_DIR = $(BUILD_DIR)

# Source files
C_SOURCES = $(SRC_DIR)/main.c \
           $(SRC_DIR)/daemon/ebpf_handler.c \
           $(SRC_DIR)/daemon/redis_client.c \
           $(SRC_DIR)/daemon/ai_engine.c \
           $(SRC_DIR)/daemon/ravn_rnn_lstm.c \
           $(SRC_DIR)/utils/logger.c

# Targets
RAVN = $(ARTIFACTS_DIR)/ravn
MODEL_HEADER = $(SRC_DIR)/daemon/codegen/model_weights.h

# eBPF object files
EBPF_OBJECTS = $(ARTIFACTS_DIR)/syscall_monitor.bpf.o \
               $(ARTIFACTS_DIR)/network_monitor.bpf.o \
               $(ARTIFACTS_DIR)/security_monitor.bpf.o \
               $(ARTIFACTS_DIR)/file_monitor.bpf.o

# Default target
all: $(RAVN)

# Generate AI model and C header
model: $(MODEL_HEADER)

$(MODEL_HEADER):
	@echo "[MODEL] Generating AI model and C header..."
	@chmod +x scripts/ai/build_model.sh
	@cd scripts/ai && ./build_model.sh
	@echo "[MODEL] Model generation completed"

# Create artifacts directory
$(ARTIFACTS_DIR):
	@mkdir -p $(ARTIFACTS_DIR)

# Main RAVN binary (eBPF + Redis + AI thread)
$(RAVN): $(C_SOURCES) $(MODEL_HEADER) | $(ARTIFACTS_DIR)
	@echo "[RAVN] Building single binary with eBPF monitoring and AI thread"
	$(CC) $(CFLAGS) -o $(RAVN) $(C_SOURCES) $(LDFLAGS)
	@echo "[RAVN] Build completed: $(RAVN)"

# eBPF object files
$(ARTIFACTS_DIR)/%.bpf.o: $(SRC_DIR)/ebpf/%.bpf.c | $(ARTIFACTS_DIR)
	@echo "[eBPF] Building $@"
	clang -O2 -target bpf -c $< -o $@

# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts"
	rm -rf $(ARTIFACTS_DIR)
	rm -f $(MODEL_HEADER)

# Start Redis server
redis:
	@echo "[REDIS] Starting Redis server"
	sudo systemctl start redis-server

.PHONY: all clean redis model
