# oh-my-safety Makefile

PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
LIBDIR    ?= $(PREFIX)/lib/oh-my-safety

VERSION := $(shell grep 'OMS_VERSION=' lib/core.sh | cut -d'"' -f2)

.PHONY: all help install uninstall test test-shell test-go lint docs build-agent build-intel build-controller packages clean

all: help

help:
	@echo "oh-my-safety v$(VERSION)"
	@echo ""
	@echo "  make install      Install to $(PREFIX)"
	@echo "  make uninstall    Remove installation"
	@echo "  make test         Run the test suite (bats if present, else a smoke scan)"
	@echo "  make test-go      Test the portable agent core"
	@echo "  make lint         Run shellcheck"
	@echo "  make docs         Regenerate docs/checks/README.md from check manifests"
	@echo "  make build-agent  Build the portable Go agent core"
	@echo "  make build-intel  Build the signed offline-intelligence CLI"
	@echo "  make build-controller  Build the self-hosted organization controller"
	@echo "  make packages     Build Linux deb/rpm/tar packages (requires nFPM)"
	@echo ""
	@echo "  PREFIX=$(PREFIX)  BINDIR=$(BINDIR)  LIBDIR=$(LIBDIR)"

install:
	@echo "Installing oh-my-safety $(VERSION) to $(PREFIX)..."
	@mkdir -p "$(BINDIR)" "$(LIBDIR)"
	@cp -R bin lib config plugins "$(LIBDIR)/"
	@if [ -d docs ]; then cp -R docs "$(LIBDIR)/"; fi
	@rm -f "$(LIBDIR)/bin/oh-my-safety-agent" "$(LIBDIR)/bin/oh-my-safety-intel" \
		"$(BINDIR)/oh-my-safety-agent" "$(BINDIR)/oh-my-safety-intel"
	@set -e; if command -v go >/dev/null 2>&1 && [ -f go.mod ]; then \
		CGO_ENABLED=0 go build -trimpath -ldflags "-X main.agentVersion=$(VERSION)" -o "$(LIBDIR)/bin/oh-my-safety-agent" ./cmd/oh-my-safety-agent; \
		CGO_ENABLED=0 go build -trimpath -o "$(LIBDIR)/bin/oh-my-safety-intel" ./cmd/oh-my-safety-intel; \
	else \
		echo "Go not found; installed the Bash compatibility runtime without portable-core commands."; \
	fi
	@chmod +x "$(LIBDIR)/bin/oh-my-safety"
	@ln -sf "$(LIBDIR)/bin/oh-my-safety" "$(BINDIR)/oh-my-safety"
	@ln -sf "$(LIBDIR)/bin/oh-my-privacy" "$(BINDIR)/oh-my-privacy"
	@if [ -x "$(LIBDIR)/bin/oh-my-safety-agent" ]; then \
		ln -sf "$(LIBDIR)/bin/oh-my-safety-agent" "$(BINDIR)/oh-my-safety-agent"; \
	fi
	@if [ -x "$(LIBDIR)/bin/oh-my-safety-intel" ]; then \
		ln -sf "$(LIBDIR)/bin/oh-my-safety-intel" "$(BINDIR)/oh-my-safety-intel"; \
	fi
	@echo "Installed: $(BINDIR)/oh-my-safety"
	@echo "Run 'oh-my-safety doctor' to get started."

uninstall:
	@echo "Uninstalling oh-my-safety..."
	@rm -f "$(BINDIR)/oh-my-safety" "$(BINDIR)/oh-my-privacy" \
		"$(BINDIR)/oh-my-safety-agent" "$(BINDIR)/oh-my-safety-intel"
	@rm -rf "$(LIBDIR)"
	@echo "Done. Config and state preserved."

test: test-shell test-go

test-shell:
	@if command -v bats >/dev/null 2>&1 && [ -d test ]; then \
		bats test; \
	else \
		echo "bats not found; running a smoke scan instead"; \
		./bin/oh-my-safety scan --offline; \
	fi

test-go:
	@go test ./...

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck --severity=warning bin/oh-my-safety bin/oh-my-privacy install.sh lib/*.sh lib/cmd/*.sh lib/platform/*.sh lib/checks/*/*.sh plugins/swiftbar/*.sh scripts/*.sh; \
		echo "Lint passed!"; \
	else \
		echo "shellcheck not found. Install with: brew install shellcheck"; exit 1; \
	fi

docs:
	@./scripts/gen-docs.sh

build-agent:
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.agentVersion=$(VERSION)" -o "dist/oh-my-safety-agent" ./cmd/oh-my-safety-agent

build-intel:
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o "dist/oh-my-safety-intel" ./cmd/oh-my-safety-intel

build-controller:
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -o "dist/oh-my-safety-controller" ./cmd/oh-my-safety-controller

packages:
	@./scripts/build-linux-packages.sh

clean:
	@rm -rf dist
