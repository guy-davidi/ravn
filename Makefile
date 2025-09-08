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
           $(SRC_DIR)/utils/logger.c

# Targets
RAVN = $(ARTIFACTS_DIR)/ravn

# eBPF object files
EBPF_OBJECTS = $(ARTIFACTS_DIR)/syscall_monitor.bpf.o \
               $(ARTIFACTS_DIR)/network_monitor.bpf.o \
               $(ARTIFACTS_DIR)/security_monitor.bpf.o \
               $(ARTIFACTS_DIR)/file_monitor.bpf.o

# Default target
all: $(RAVN)

# Create artifacts directory
$(ARTIFACTS_DIR):
	@mkdir -p $(ARTIFACTS_DIR)

# Main RAVN binary (eBPF + Redis + AI thread)
$(RAVN): $(C_SOURCES) | $(ARTIFACTS_DIR)
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

# Install dependencies
deps:
	@echo "[DEPS] Installing system dependencies"
	sudo apt update
	sudo apt install -y build-essential clang llvm libbpf-dev libhiredis-dev redis-server

# Start Redis server
redis:
	@echo "[REDIS] Starting Redis server"
	sudo systemctl start redis-server

# Run daemon mode
daemon: $(RAVN)
	@echo "[DAEMON] Starting RAVN daemon with AI thread"
	sudo $(RAVN) daemon

# Run CLI mode
cli: $(RAVN)
	@echo "[CLI] Starting RAVN CLI dashboard"
	$(RAVN) cli

# Test the system
test: $(RAVN)
	@echo "[TEST] Testing RAVN system with AI thread"
	# Start daemon in background
	sudo $(RAVN) daemon &
	# Wait a moment for daemon to start
	sleep 2
	# Start CLI
	$(RAVN) cli

# Help
help:
	@echo "RAVN Security Platform Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build complete RAVN system (single binary with AI thread)"
	@echo "  clean    - Remove all build artifacts"
	@echo "  deps     - Install system dependencies"
	@echo "  redis    - Start Redis server"
	@echo "  daemon   - Run RAVN daemon (eBPF + Redis + AI thread)"
	@echo "  cli      - Run RAVN CLI dashboard"
	@echo "  test     - Test complete system (daemon + CLI)"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make all     # Build everything (single binary with AI thread)"
	@echo "  make daemon  # Run daemon: sudo ./artifacts/ravn daemon"
	@echo "  make cli     # Run CLI: ./artifacts/ravn cli"
	@echo "  make test    # Test complete system"

.PHONY: all clean deps redis daemon cli test help
