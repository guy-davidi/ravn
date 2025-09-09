# RAVN Security Platform Makefile
# Pure C implementation with daemon and CLI modes
# Smart build system with network change detection

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I$(SRC_DIR)
LDFLAGS = -lbpf -lhiredis -lpthread -lm

# Directories
SRC_DIR = src
BUILD_DIR = artifacts
ARTIFACTS_DIR = $(BUILD_DIR)

# Network-related files that require model retraining
NETWORK_FILES = $(SRC_DIR)/daemon/ai_engine.c \
                $(SRC_DIR)/daemon/ai_engine.h \
                $(SRC_DIR)/daemon/ravn_lstm.h \
                $(SRC_DIR)/daemon/ravn_rnn_lstm.c \
                $(SRC_DIR)/daemon/codegen/model_weights.h \
                scripts/ai/train_model.py \
                scripts/ai/build_model.sh

# Network change tracking
NETWORK_HASH_FILE = $(ARTIFACTS_DIR)/.network_hash

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

# Smart network change detection
check-network-changes:
	@scripts/check_network_changes.sh

# Ask user before training model
ask-model-training:
	@scripts/ask_model_training.sh

# Generate AI model and C header (only when needed)
model: check-network-changes ask-model-training
	@if [ -f $(ARTIFACTS_DIR)/.train_model ]; then \
		TRAIN_MODEL=$$(cat $(ARTIFACTS_DIR)/.train_model | cut -d'=' -f2); \
		if [ "$$TRAIN_MODEL" = "1" ]; then \
			$(MAKE) $(MODEL_HEADER); \
		else \
			echo "[SMART] Skipping model training as requested"; \
		fi; \
	else \
		$(MAKE) $(MODEL_HEADER); \
	fi

$(MODEL_HEADER):
	@echo "[MODEL] Generating AI model and C header..."
	@chmod +x scripts/ai/build_model.sh
	@cd scripts/ai && ./build_model.sh
	@echo "[MODEL] Model generation completed"

# Force model regeneration (always asks)
force-model:
	@echo ""
	@echo "🤖 FORCE MODEL RETRAINING"
	@echo "========================="
	@echo "This will force retrain the AI model regardless of code changes."
	@echo "This process may take several minutes."
	@echo ""
	@read -p "Are you sure you want to force retrain the model? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		echo "[MODEL] User confirmed - force regenerating AI model and C header..."; \
		rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE); \
		$(MAKE) $(MODEL_HEADER); \
	else \
		echo "[MODEL] User declined - skipping force model retraining"; \
	fi

# Create artifacts directory
$(ARTIFACTS_DIR):
	@mkdir -p $(ARTIFACTS_DIR)

# Object files for incremental builds
OBJECTS = $(ARTIFACTS_DIR)/main.o \
          $(ARTIFACTS_DIR)/ebpf_handler.o \
          $(ARTIFACTS_DIR)/redis_client.o \
          $(ARTIFACTS_DIR)/ai_engine.o \
          $(ARTIFACTS_DIR)/ravn_rnn_lstm.o \
          $(ARTIFACTS_DIR)/logger.o

# Main RAVN binary (eBPF + Redis + AI thread)
$(RAVN): $(OBJECTS) $(MODEL_HEADER) | $(ARTIFACTS_DIR)
	@echo "[RAVN] Linking single binary with eBPF monitoring and AI thread"
	$(CC) $(CFLAGS) -o $(RAVN) $(OBJECTS) $(LDFLAGS)
	@echo "[RAVN] Build completed: $(RAVN)"

# Individual object file rules
$(ARTIFACTS_DIR)/main.o: $(SRC_DIR)/main.c $(MODEL_HEADER) | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(ARTIFACTS_DIR)/ebpf_handler.o: $(SRC_DIR)/daemon/ebpf_handler.c | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(ARTIFACTS_DIR)/redis_client.o: $(SRC_DIR)/daemon/redis_client.c | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(ARTIFACTS_DIR)/ai_engine.o: $(SRC_DIR)/daemon/ai_engine.c $(MODEL_HEADER) | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(ARTIFACTS_DIR)/ravn_rnn_lstm.o: $(SRC_DIR)/daemon/ravn_rnn_lstm.c $(MODEL_HEADER) | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(ARTIFACTS_DIR)/logger.o: $(SRC_DIR)/utils/logger.c | $(ARTIFACTS_DIR)
	@echo "[CC] Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# eBPF object files
$(ARTIFACTS_DIR)/%.bpf.o: $(SRC_DIR)/ebpf/%.bpf.c | $(ARTIFACTS_DIR)
	@echo "[eBPF] Building $@"
	clang -O2 -target bpf -c $< -o $@

# Ask user before cleaning network artifacts
ask-clean-network:
	@if [ -f $(MODEL_HEADER) ] || [ -f $(NETWORK_HASH_FILE) ]; then \
		echo ""; \
		echo "🧹 CLEAN NETWORK ARTIFACTS"; \
		echo "==========================="; \
		echo "This will remove the trained AI model and network artifacts."; \
		echo "You will need to retrain the model on next build."; \
		echo ""; \
		read -p "Do you want to remove network artifacts? [y/N]: " confirm; \
		if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
			echo "[CLEAN] User confirmed - removing network artifacts..."; \
			echo "CLEAN_NETWORK=1" > $(ARTIFACTS_DIR)/.clean_network; \
		else \
			echo "[CLEAN] User declined - keeping network artifacts"; \
			echo "CLEAN_NETWORK=0" > $(ARTIFACTS_DIR)/.clean_network; \
		fi; \
	else \
		echo "CLEAN_NETWORK=0" > $(ARTIFACTS_DIR)/.clean_network; \
	fi

# Clean build artifacts (asks before removing network)
clean: ask-clean-network
	@echo "[CLEAN] Removing build artifacts"
	@if [ -f $(ARTIFACTS_DIR)/.clean_network ]; then \
		CLEAN_NETWORK=$$(cat $(ARTIFACTS_DIR)/.clean_network); \
		if [ "$$CLEAN_NETWORK" = "1" ]; then \
			echo "[CLEAN] Removing network artifacts as requested"; \
			rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE); \
		else \
			echo "[CLEAN] Preserving network artifacts as requested"; \
		fi; \
	fi
	@rm -rf $(ARTIFACTS_DIR)
	@echo "[CLEAN] Build artifacts removed"

# Clean everything including network (force clean)
clean-all:
	@echo ""
	@echo "🧹 FORCE CLEAN ALL"
	@echo "=================="
	@echo "This will remove ALL build artifacts including the trained AI model."
	@echo "You will need to retrain the model on next build."
	@echo ""
	@read -p "Are you sure you want to remove everything? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		echo "[CLEAN] User confirmed - removing all artifacts..."; \
		rm -rf $(ARTIFACTS_DIR); \
		rm -f $(MODEL_HEADER); \
		echo "[CLEAN] All artifacts removed"; \
	else \
		echo "[CLEAN] User declined - keeping artifacts"; \
	fi

# Start Redis server
redis:
	@echo "[REDIS] Starting Redis server"
	sudo systemctl start redis-server

# Help target
help:
	@echo "RAVN Security Platform - Smart Build System"
	@echo "==========================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build RAVN with smart network detection"
	@echo "  model        - Train AI model (asks if network code changed)"
	@echo "  force-model  - Force retrain AI model (always asks)"
	@echo "  clean        - Clean build artifacts (asks before removing network)"
	@echo "  clean-all    - Force clean everything including network (always asks)"
	@echo "  redis        - Start Redis server"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Smart Features:"
	@echo "  - Detects network code changes automatically"
	@echo "  - Asks before expensive model training"
	@echo "  - Preserves trained models when possible"
	@echo "  - Skips unnecessary rebuilds"

.PHONY: all clean clean-all redis model force-model check-network-changes ask-model-training ask-clean-network help
