# RAVN Security Platform Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -Isrc
LDFLAGS = -lbpf -lhiredis -lpthread -lm

SRC_DIR = src
ARTIFACTS_DIR = artifacts
RAVN = $(ARTIFACTS_DIR)/ravn
MODEL_HEADER = $(SRC_DIR)/daemon/codegen/model_weights.h
VERSION_HEADER = $(SRC_DIR)/version.h
NETWORK_HASH_FILE = $(ARTIFACTS_DIR)/.network_hash

C_SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/daemon/ebpf_handler.c $(SRC_DIR)/daemon/redis_client.c \
           $(SRC_DIR)/daemon/ai_engine.c $(SRC_DIR)/daemon/ravn_rnn_lstm.c $(SRC_DIR)/utils/logger.c
OBJECTS = $(C_SOURCES:$(SRC_DIR)/%.c=$(ARTIFACTS_DIR)/%.o)
EBPF_OBJECTS = $(ARTIFACTS_DIR)/syscall_monitor.bpf.o $(ARTIFACTS_DIR)/network_monitor.bpf.o \
               $(ARTIFACTS_DIR)/security_monitor.bpf.o $(ARTIFACTS_DIR)/file_monitor.bpf.o \
               $(ARTIFACTS_DIR)/memory_monitor.bpf.o $(ARTIFACTS_DIR)/process_monitor.bpf.o \
               $(ARTIFACTS_DIR)/kernel_monitor.bpf.o $(ARTIFACTS_DIR)/performance_monitor.bpf.o

all: $(VERSION_HEADER) $(MODEL_HEADER) $(EBPF_OBJECTS) $(RAVN)

$(ARTIFACTS_DIR):
	@mkdir -p $@

$(VERSION_HEADER):
	@echo "[VERSION] Generating version information..."
	@./scripts/version.sh update

$(MODEL_HEADER):
	@echo "[MODEL] Generating AI model..."
	@chmod +x scripts/ai/build_model.sh && cd scripts/ai && ./build_model.sh

model: $(MODEL_HEADER)

version:
	@./scripts/version.sh show

version-update:
	@./scripts/version.sh update

version-force:
	@./scripts/version.sh force

version-reset:
	@./scripts/version.sh reset

release-local:
	@./scripts/release.sh local

release-tag:
	@./scripts/release.sh tag

release-github:
	@./scripts/release.sh github

release-full:
	@./scripts/release.sh full

release-list:
	@./scripts/release.sh list

package:
	@echo "[PACKAGE] Building Docker package..."
	@docker build -t ravn:latest .
	@echo "[PACKAGE] Package built successfully: ravn:latest"

package-push:
	@echo "[PACKAGE] Pushing to GitHub Container Registry (PRIVATE)..."
	@echo "[PACKAGE] Note: Package will be private by default"
	@docker tag ravn:latest ghcr.io/guy-davidi/ravn:latest
	@docker push ghcr.io/guy-davidi/ravn:latest
	@echo "[PACKAGE] Package pushed successfully to private registry"

force-model:
	@read -p "Force retrain model? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE) && $(MAKE) $(MODEL_HEADER); \
	fi

$(RAVN): $(OBJECTS) | $(ARTIFACTS_DIR)
	@echo "[RAVN] Linking..."
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

$(ARTIFACTS_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Specific dependencies for files that need headers
$(ARTIFACTS_DIR)/main.o: $(VERSION_HEADER)
$(ARTIFACTS_DIR)/ai_engine.o: $(MODEL_HEADER)
$(ARTIFACTS_DIR)/ravn_rnn_lstm.o: $(MODEL_HEADER)

# eBPF compilation flags
CLANG_FLAGS = -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -I$(SRC_DIR)

# Generate vmlinux.h if needed
$(SRC_DIR)/vmlinux.h:
	@echo "[eBPF] Generating vmlinux.h"
	@if command -v bpftool >/dev/null 2>&1; then \
		sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SRC_DIR)/vmlinux.h; \
	else \
		echo "[eBPF] bpftool not available, using minimal vmlinux.h"; \
	fi

$(ARTIFACTS_DIR)/%.bpf.o: $(SRC_DIR)/ebpf/%.bpf.c $(SRC_DIR)/vmlinux.h
	@mkdir -p $(dir $@)
	@echo "[eBPF] $@"
	clang $(CLANG_FLAGS) -c $< -o $@

clean:
	@read -p "Remove network artifacts? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE); \
	fi
	@rm -rf $(ARTIFACTS_DIR)

clean-ci:
	@echo "[CLEAN] Removing all artifacts for CI build"
	@rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE)
	@rm -rf $(ARTIFACTS_DIR)

clean-all:
	@read -p "Remove ALL artifacts? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -rf $(ARTIFACTS_DIR) $(MODEL_HEADER); \
	fi

redis:
	@echo "[REDIS] Starting Redis..."
	sudo systemctl start redis-server

format-check:
	@echo "[FORMAT] Checking code formatting..."
	@./scripts/format_code.sh --check

format-fix:
	@echo "[FORMAT] Applying code formatting..."
	@./scripts/format_code.sh --fix

format: format-fix

help:
	@echo "RAVN Security Platform"
	@echo "Targets:"
	@echo "  all            - Build RAVN with version and model"
	@echo "  model          - Train AI model"
	@echo "  force-model    - Force retrain AI model"
	@echo "  version        - Show current version"
	@echo "  version-update - Update version (if changes detected)"
	@echo "  version-force  - Force version update"
	@echo "  version-reset  - Reset version to current date.1"
	@echo "  release-local  - Create local release"
	@echo "  release-tag    - Create git tag"
	@echo "  release-github - Trigger GitHub release"
	@echo "  release-full   - Full release process (local + tag + github)"
	@echo "  release-list   - List existing releases"
	@echo "  package        - Build Docker package"
	@echo "  package-push   - Push Docker package to GitHub Container Registry"
	@echo "  format-check   - Check code formatting (Linux kernel style)"
	@echo "  format-fix     - Apply code formatting to all files"
	@echo "  format         - Alias for format-fix"
	@echo "  clean          - Clean build artifacts (interactive)"
	@echo "  clean-ci       - Clean build artifacts (non-interactive for CI)"
	@echo "  clean-all      - Force clean everything"
	@echo "  redis          - Start Redis server"
	@echo "  help           - Show this help"

.PHONY: all clean clean-ci clean-all redis model force-model version version-update version-force version-reset release-local release-tag release-github release-full release-list package package-push format-check format-fix format help
