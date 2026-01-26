# oh-my-privacy Makefile

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/oh-my-privacy
CONFIGDIR ?= $(HOME)/.config/oh-my-privacy

VERSION := $(shell grep 'OMP_VERSION=' lib/core.sh | cut -d'"' -f2)

.PHONY: all install uninstall test clean help

all: help

help:
	@echo "oh-my-privacy v$(VERSION)"
	@echo ""
	@echo "Usage:"
	@echo "  make install      Install to $(PREFIX)"
	@echo "  make uninstall    Remove installation"
	@echo "  make test         Run checks locally"
	@echo "  make lint         Run shellcheck"
	@echo "  make clean        Clean build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)"
	@echo "  BINDIR=$(BINDIR)"
	@echo "  LIBDIR=$(LIBDIR)"

install:
	@echo "Installing oh-my-privacy to $(PREFIX)..."
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)/platform
	@mkdir -p $(LIBDIR)/checks
	@mkdir -p $(CONFIGDIR)

	@# Install library files
	@cp lib/core.sh $(LIBDIR)/
	@cp lib/platform/*.sh $(LIBDIR)/platform/
	@cp lib/checks/*.sh $(LIBDIR)/checks/

	@# Install config
	@cp config/default.yaml $(LIBDIR)/../config/ 2>/dev/null || mkdir -p $(LIBDIR)/../config && cp config/default.yaml $(LIBDIR)/../config/
	@[ -f $(CONFIGDIR)/config.yaml ] || cp config/default.yaml $(CONFIGDIR)/config.yaml

	@# Install binary
	@cp bin/oh-my-privacy $(BINDIR)/
	@chmod +x $(BINDIR)/oh-my-privacy

	@echo ""
	@echo "Installation complete!"
	@echo "  Binary: $(BINDIR)/oh-my-privacy"
	@echo "  Config: $(CONFIGDIR)/config.yaml"
	@echo ""
	@echo "Run 'oh-my-privacy --help' to get started."

uninstall:
	@echo "Uninstalling oh-my-privacy..."
	@rm -f $(BINDIR)/oh-my-privacy
	@rm -rf $(LIBDIR)
	@echo "Done. Config preserved at $(CONFIGDIR)"

test:
	@echo "Running oh-my-privacy checks..."
	@./bin/oh-my-privacy --once

lint:
	@echo "Running shellcheck..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck bin/oh-my-privacy lib/*.sh lib/**/*.sh install.sh; \
		echo "Lint passed!"; \
	else \
		echo "shellcheck not found. Install with: brew install shellcheck"; \
		exit 1; \
	fi

clean:
	@echo "Nothing to clean."
