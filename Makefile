# RAVN Security Platform Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -Isrc
LDFLAGS = -lbpf -lhiredis -lpthread -lm

SRC_DIR = src
ARTIFACTS_DIR = artifacts
RAVN = $(ARTIFACTS_DIR)/ravn
MODEL_HEADER = $(SRC_DIR)/daemon/codegen/model_weights.h
NETWORK_HASH_FILE = $(ARTIFACTS_DIR)/.network_hash

C_SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/daemon/ebpf_handler.c $(SRC_DIR)/daemon/redis_client.c \
           $(SRC_DIR)/daemon/ai_engine.c $(SRC_DIR)/daemon/ravn_rnn_lstm.c $(SRC_DIR)/utils/logger.c
OBJECTS = $(C_SOURCES:$(SRC_DIR)/%.c=$(ARTIFACTS_DIR)/%.o)
EBPF_OBJECTS = $(ARTIFACTS_DIR)/syscall_monitor.bpf.o $(ARTIFACTS_DIR)/network_monitor.bpf.o \
               $(ARTIFACTS_DIR)/security_monitor.bpf.o $(ARTIFACTS_DIR)/file_monitor.bpf.o

all: $(MODEL_HEADER) $(RAVN)

$(ARTIFACTS_DIR):
	@mkdir -p $@

$(MODEL_HEADER):
	@echo "[MODEL] Generating AI model..."
	@chmod +x scripts/ai/build_model.sh && cd scripts/ai && ./build_model.sh

model: $(MODEL_HEADER)

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

# Specific dependencies for files that need model header
$(ARTIFACTS_DIR)/ai_engine.o: $(MODEL_HEADER)
$(ARTIFACTS_DIR)/ravn_rnn_lstm.o: $(MODEL_HEADER)

$(ARTIFACTS_DIR)/%.bpf.o: $(SRC_DIR)/ebpf/%.bpf.c
	@mkdir -p $(dir $@)
	@echo "[eBPF] $@"
	clang -O2 -target bpf -c $< -o $@

clean:
	@read -p "Remove network artifacts? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -f $(MODEL_HEADER) $(NETWORK_HASH_FILE); \
	fi
	@rm -rf $(ARTIFACTS_DIR)

clean-all:
	@read -p "Remove ALL artifacts? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		rm -rf $(ARTIFACTS_DIR) $(MODEL_HEADER); \
	fi

redis:
	@echo "[REDIS] Starting Redis..."
	sudo systemctl start redis-server

help:
	@echo "RAVN Security Platform"
	@echo "Targets: all, model, force-model, clean, clean-all, redis, help"

.PHONY: all clean clean-all redis model force-model help
