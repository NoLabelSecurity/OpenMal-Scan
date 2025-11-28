# Programmer:      Brian Lorick
# Date:            **/**/****
# Project:         Malware Scanner
# Description:     Makefile for building the modular malware scanner project
#                  with support for OpenSSL hashing, recursion scanning,
#                  monitoring, and utility modules.

# ============================================================
# CONFIGURATION
# ============================================================

CC                := gcc                   # C compiler
CFLAGS            := -Wall -Wextra -std=c11 -Iinclude
LDFLAGS           := -lcrypto              # Link OpenSSL crypto library
BUILD_DIR         := build                 # Output directory
TARGET            := $(BUILD_DIR)/malware_scanner

SRC_DIR           := src                   # Source directory
INC_DIR           := include               # Header directory

# Source files
SRCS := \
    $(SRC_DIR)/main.c \
    $(SRC_DIR)/scanner.c \
    $(SRC_DIR)/hash.c \
    $(SRC_DIR)/monitor.c \
    $(SRC_DIR)/utils.c

# Object output files
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Dependency files
DEPS := $(OBJS:.o=.d)

# ============================================================
# BUILD TARGETS
# ============================================================

# Default build = Release
all: release

# -------------------------
# Release Build
# -------------------------
release: CFLAGS += -O2
release: $(TARGET)
	@echo "Build complete: RELEASE mode"

# -------------------------
# Debug Build
# -------------------------
debug: CFLAGS += -g -O0
debug: $(TARGET)
	@echo "Build complete: DEBUG mode"

# -------------------------
# Linking Final Executable
# -------------------------
$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# -------------------------
# Compiling Object Files
# Adds -MMD -MP for auto dependency generation
# -------------------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Create build directory if missing
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# ============================================================
# UTILITY TARGETS
# ============================================================

# Clean all build files
clean:
	rm -rf $(BUILD_DIR)
	@echo "Clean complete."

# Rebuild everything from scratch
rebuild: clean all

# Run the scanner (main executable)
run: $(TARGET)
	$(TARGET)

# Show available options
help:
	@echo ""
	@echo "MalwareScanner Makefile Commands:"
	@echo "  make          - Build release version"
	@echo "  make debug    - Build debug version"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make run      - Run the malware scanner"
	@echo "  make rebuild  - Clean and build fresh"
	@echo ""

# ============================================================
# Include dependency files (auto-generated)
# ============================================================

-include $(DEPS)

# End of Makefile
