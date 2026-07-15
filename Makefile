# oh-my-safety Makefile

PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
LIBDIR    ?= $(PREFIX)/lib/oh-my-safety

VERSION := $(shell grep 'OMS_VERSION=' lib/core.sh | cut -d'"' -f2)

.PHONY: all help install uninstall test lint docs clean

all: help

help:
	@echo "oh-my-safety v$(VERSION)"
	@echo ""
	@echo "  make install      Install to $(PREFIX)"
	@echo "  make uninstall    Remove installation"
	@echo "  make test         Run the test suite (bats if present, else a smoke scan)"
	@echo "  make lint         Run shellcheck"
	@echo "  make docs         Regenerate docs/checks/README.md from check manifests"
	@echo ""
	@echo "  PREFIX=$(PREFIX)  BINDIR=$(BINDIR)  LIBDIR=$(LIBDIR)"

install:
	@echo "Installing oh-my-safety $(VERSION) to $(PREFIX)..."
	@mkdir -p $(BINDIR) $(LIBDIR)
	@cp -R bin lib config $(LIBDIR)/
	@[ -d docs ] && cp -R docs $(LIBDIR)/ || true
	@chmod +x $(LIBDIR)/bin/oh-my-safety
	@ln -sf $(LIBDIR)/bin/oh-my-safety $(BINDIR)/oh-my-safety
	@ln -sf $(LIBDIR)/bin/oh-my-privacy $(BINDIR)/oh-my-privacy
	@echo "Installed: $(BINDIR)/oh-my-safety"
	@echo "Run 'oh-my-safety doctor' to get started."

uninstall:
	@echo "Uninstalling oh-my-safety..."
	@rm -f $(BINDIR)/oh-my-safety $(BINDIR)/oh-my-privacy
	@rm -rf $(LIBDIR)
	@echo "Done. Config and state preserved."

test:
	@if command -v bats >/dev/null 2>&1 && [ -d test ]; then \
		bats test; \
	else \
		echo "bats not found; running a smoke scan instead"; \
		./bin/oh-my-safety scan --offline; \
	fi

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck bin/oh-my-safety bin/oh-my-privacy install.sh lib/*.sh lib/cmd/*.sh lib/platform/*.sh lib/checks/*/*.sh plugins/swiftbar/*.sh scripts/*.sh; \
		echo "Lint passed!"; \
	else \
		echo "shellcheck not found. Install with: brew install shellcheck"; exit 1; \
	fi

docs:
	@./scripts/gen-docs.sh

clean:
	@echo "Nothing to clean."
