# SPDX-License-Identifier: GPL-2.0
#
# ravn Makefile
#
# This Makefile builds the ravn layered architecture components:
# - Core Layer: eBPF programs and kernel interfaces
# - Application Layer: CLI and dashboard interfaces
#
# Author: ravn Security Team
# Date: 2025

# Build configuration
CC := gcc
CLANG := clang
RUSTC := cargo
CFLAGS := -O2 -g -Wall -Wextra -Werror
RUSTFLAGS := --release

# Directories - All build outputs go to artifacts/
BUILD_DIR := artifacts/build
ARTIFACTS_DIR := artifacts
INCLUDE_DIR := include
SRC_DIR := src
LIB_DIR := artifacts/lib
TOOLS_DIR := tools
SCRIPTS_DIR := scripts
DOCS_DIR := docs

# Layer directories
CORE_DIR := $(SRC_DIR)/core
ABSTRACTION_DIR := $(SRC_DIR)/abstraction
SERVICE_DIR := $(SRC_DIR)/service
APP_DIR := $(SRC_DIR)/app
STORAGE_DIR := $(SRC_DIR)/storage
EBPF_DIR := $(SRC_DIR)/ebpf
SECURITY_DIR := $(SRC_DIR)/security

# eBPF programs
BPF_PROGRAMS := core_execfs core_network core_system core_security core_vulnerability core_update-checker
BPF_OBJECTS := $(addprefix $(BUILD_DIR)/,$(addsuffix .bpf.o,$(BPF_PROGRAMS)))

# Core layer components
CORE_SOURCES := $(wildcard $(CORE_DIR)/*.c)
CORE_OBJECTS := $(addprefix $(BUILD_DIR)/core-,$(notdir $(CORE_SOURCES:.c=.o)))

# Abstraction layer components
ABSTRACTION_SOURCES := $(wildcard $(ABSTRACTION_DIR)/*.c)
ABSTRACTION_OBJECTS := $(addprefix $(BUILD_DIR)/abstraction-,$(notdir $(ABSTRACTION_SOURCES:.c=.o)))

# Service layer components
SERVICE_SOURCES := $(wildcard $(SERVICE_DIR)/*.c)
SERVICE_OBJECTS := $(addprefix $(BUILD_DIR)/service-,$(notdir $(SERVICE_SOURCES:.c=.o)))

# Application layer components
APP_SOURCES := $(wildcard $(APP_DIR)/*.c)
APP_OBJECTS := $(addprefix $(BUILD_DIR)/app-,$(notdir $(APP_SOURCES:.c=.o)))

# Storage layer components
STORAGE_SOURCES := $(wildcard $(STORAGE_DIR)/*.c)
STORAGE_OBJECTS := $(addprefix $(BUILD_DIR)/storage-,$(notdir $(STORAGE_SOURCES:.c=.o)))

# eBPF layer components
EBPF_SOURCES := $(wildcard $(EBPF_DIR)/*.c)
EBPF_OBJECTS := $(addprefix $(BUILD_DIR)/ebpf-,$(notdir $(EBPF_SOURCES:.c=.o)))

# Security layer components
SECURITY_SOURCES := $(wildcard $(SECURITY_DIR)/*.c)
SECURITY_OBJECTS := $(addprefix $(BUILD_DIR)/security-,$(notdir $(SECURITY_SOURCES:.c=.o)))

# Libraries
CORE_LIB := $(LIB_DIR)/libravn-core.a
ABSTRACTION_LIB := $(LIB_DIR)/libravn-abstraction.a
SERVICE_LIB := $(LIB_DIR)/libravn-service.a
STORAGE_LIB := $(LIB_DIR)/libravn-storage.a
EBPF_LIB := $(LIB_DIR)/libravn-ebpf.a
SECURITY_LIB := $(LIB_DIR)/libravn-security.a

# Executables
AGENT := $(ARTIFACTS_DIR)/ravn
CLI := $(ARTIFACTS_DIR)/ravn-ctl

# Include paths
INCLUDES := -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/core -I$(INCLUDE_DIR)/abstraction -I$(INCLUDE_DIR)/service -I$(INCLUDE_DIR)/app -I$(INCLUDE_DIR)/storage -I$(INCLUDE_DIR)/ebpf -I$(INCLUDE_DIR)/security -I$(SRC_DIR)/core/ebpf

# Library paths and libraries
LIBPATHS := -L$(LIB_DIR)
LIBS := -lbpf -lelf -lz -lsqlite3 -lm -lpthread

# Default target
.PHONY: all
all: $(AGENT) $(CLI) $(RAVN)

# Create directories
$(BUILD_DIR) $(ARTIFACTS_DIR) $(LIB_DIR):
	@mkdir -p $@

# eBPF program compilation
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/core/ebpf/%.bpf.c | $(BUILD_DIR)
	@echo "[eBPF] Building $@"
	$(CLANG) -O2 -g -Wall -Wextra -target bpf -c $< -o $@

# Core layer compilation
$(BUILD_DIR)/core-%.o: $(CORE_DIR)/%.c | $(BUILD_DIR)
	@echo "[CORE] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Abstraction layer compilation
$(BUILD_DIR)/abstraction-%.o: $(ABSTRACTION_DIR)/%.c | $(BUILD_DIR)
	@echo "[ABSTRACTION] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Service layer compilation
$(BUILD_DIR)/service-%.o: $(SERVICE_DIR)/%.c | $(BUILD_DIR)
	@echo "[SERVICE] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Application layer compilation
$(BUILD_DIR)/app-%.o: $(APP_DIR)/%.c | $(BUILD_DIR)
	@echo "[APP] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Storage layer compilation
$(BUILD_DIR)/storage-%.o: $(STORAGE_DIR)/%.c | $(BUILD_DIR)
	@echo "[STORAGE] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# eBPF layer compilation
$(BUILD_DIR)/ebpf-%.o: $(EBPF_DIR)/%.c | $(BUILD_DIR)
	@echo "[EBPF] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Security layer compilation
$(BUILD_DIR)/security-%.o: $(SECURITY_DIR)/%.c | $(BUILD_DIR)
	@echo "[SECURITY] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Static libraries
$(CORE_LIB): $(CORE_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

$(ABSTRACTION_LIB): $(ABSTRACTION_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

$(SERVICE_LIB): $(SERVICE_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

$(STORAGE_LIB): $(STORAGE_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

$(EBPF_LIB): $(EBPF_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

$(SECURITY_LIB): $(SECURITY_OBJECTS) | $(LIB_DIR)
	@echo "[LIB] Creating $@"
	ar rcs $@ $^

# Agent executable (integrated with all layers)
$(AGENT): $(CORE_LIB) $(ABSTRACTION_LIB) $(SERVICE_LIB) $(APP_OBJECTS) $(BPF_OBJECTS) | $(ARTIFACTS_DIR)
	@echo "[AGENT] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_DIR)/core/core_agent_main.c $(APP_OBJECTS) -o $@ $(LIBPATHS) -lravn-service -lravn-abstraction -lravn-core $(LIBS)

# RAVN cutting-edge eBPF executable (demonstrates CRUD operations)
RAVN := $(ARTIFACTS_DIR)/ravn
$(RAVN): $(STORAGE_LIB) $(EBPF_LIB) $(SECURITY_LIB) $(BPF_OBJECTS) | $(ARTIFACTS_DIR)
	@echo "[RAVN] Building $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_DIR)/ravn.c -o $@ $(LIBPATHS) -lravn-storage -lravn-ebpf -lravn-security $(LIBS)
	@echo "[RAVN] Copying eBPF object files"
	@cp $(BPF_OBJECTS) $(ARTIFACTS_DIR)/

# CLI executable (Rust)
$(CLI): $(SRC_DIR)/app/cli/Cargo.toml | $(ARTIFACTS_DIR)
	@echo "[CLI] Building $@"
	cd $(SRC_DIR)/app/cli && CARGO_TARGET_DIR=$(CURDIR)/$(BUILD_DIR)/cli CARGO_HOME=$(CURDIR)/$(BUILD_DIR)/cargo-home $(RUSTC) build $(RUSTFLAGS) --features tui
	@cp $(BUILD_DIR)/cli/release/ravn-ctl $@

# Layer-specific targets
.PHONY: core
core: $(CORE_LIB) $(BPF_OBJECTS)

.PHONY: ravn
ravn: $(RAVN)

.PHONY: abstraction
abstraction: $(ABSTRACTION_LIB)

.PHONY: service
service: $(SERVICE_LIB)

.PHONY: app
app: $(CLI)

.PHONY: agent
agent: $(AGENT)

.PHONY: cli
cli: $(CLI)

# Development targets
.PHONY: debug
debug: CFLAGS += -DDEBUG -g3
debug: RUSTFLAGS += --debug
debug: $(AGENT) $(CLI)

.PHONY: test
test: $(AGENT) $(CLI)
	@echo "[TEST] Running tests"
	@if [ -f scripts/test.sh ]; then ./scripts/test.sh; fi

.PHONY: install
install: $(AGENT) $(CLI)
	@echo "[INSTALL] Installing ravn"
	@sudo cp $(AGENT) /usr/local/bin/
	@sudo cp $(CLI) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/ravn
	@sudo chmod +x /usr/local/bin/ravn-ctl

.PHONY: uninstall
uninstall:
	@echo "[UNINSTALL] Removing ravn"
	@sudo rm -f /usr/local/bin/ravn
	@sudo rm -f /usr/local/bin/ravn-ctl

# Documentation targets
.PHONY: docs
docs:
	@echo "[DOCS] Generating documentation"
	@if [ -f scripts/generate-docs.sh ]; then ./scripts/generate-docs.sh; fi

.PHONY: man
man:
	@echo "[MAN] Generating man pages"
	@if [ -f scripts/generate-man.sh ]; then ./scripts/generate-man.sh; fi

# Cleanup targets
.PHONY: clean
clean:
	@echo "[CLEAN] Cleaning build artifacts"
	@rm -rf $(ARTIFACTS_DIR)
	@rm -rf .cache/
	@rm -f *.db *.db-journal

.PHONY: distclean
distclean: clean
	@echo "[DISTCLEAN] Cleaning all generated files"
	@rm -rf .cache/
	@rm -f *.db *.db-journal

# Help target
.PHONY: help
help:
	@echo "ravn Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all components (default)"
	@echo "  core         - Build core layer (eBPF programs, kernel interfaces)"
	@echo "  abstraction  - Build abstraction layer (event processing)"
	@echo "  service      - Build service layer (security services)"
	@echo "  app          - Build application layer (CLI, dashboard)"
	@echo "  agent        - Build eBPF agent"
	@echo "  cli          - Build CLI tool"
	@echo "  debug        - Build with debug symbols"
	@echo "  test         - Run tests"
	@echo "  install      - Install to system"
	@echo "  uninstall    - Remove from system"
	@echo "  docs         - Generate documentation"
	@echo "  man          - Generate man pages"
	@echo "  clean        - Clean build artifacts"
	@echo "  distclean    - Clean all generated files"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Architecture:"
	@echo "  Core Layer      - eBPF programs, ring buffers, kernel interfaces"
	@echo "  Abstraction     - Event processing, data structures, interfaces"
	@echo "  Service Layer   - Security services, anomaly detection, monitoring"
	@echo "  Application     - CLI, dashboard, configuration management"
	@echo ""
	@echo "Directories:"
	@echo "  $(INCLUDE_DIR)/ - Header files by layer"
	@echo "  $(SRC_DIR)/     - Source code by layer"
	@echo "  $(LIB_DIR)/     - Static libraries by layer"
	@echo "  $(BUILD_DIR)/   - Build artifacts"
	@echo "  $(ARTIFACTS_DIR)/ - Executable binaries"

# Dependencies
$(CORE_OBJECTS): $(wildcard $(INCLUDE_DIR)/core/*.h)
$(ABSTRACTION_OBJECTS): $(wildcard $(INCLUDE_DIR)/abstraction/*.h)
$(SERVICE_OBJECTS): $(wildcard $(INCLUDE_DIR)/service/*.h)
$(APP_OBJECTS): $(wildcard $(INCLUDE_DIR)/app/*.h)

# Ensure directories exist before building
$(CORE_OBJECTS) $(ABSTRACTION_OBJECTS) $(SERVICE_OBJECTS) $(APP_OBJECTS): | $(BUILD_DIR)
$(BPF_OBJECTS): | $(BUILD_DIR)
$(CORE_LIB) $(ABSTRACTION_LIB) $(SERVICE_LIB): | $(LIB_DIR)
$(AGENT) $(CLI): | $(ARTIFACTS_DIR)