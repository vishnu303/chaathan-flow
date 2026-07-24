# Chaathan - Pentesting Recon Framework
# Makefile for build, install, and development tasks

SHELL := /bin/bash
BINARY_NAME := chaathan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOFLAGS := -buildvcs=false -ldflags "-s -w -X github.com/vishnu303/chaathan/cli.Version=$(VERSION) -X github.com/vishnu303/chaathan/cli.BuildTime=$(BUILD_TIME)"
INSTALL_DIR := /usr/local/bin
GO_BIN := $(shell command -v go 2>/dev/null || echo "/usr/local/go/bin/go")

# ANSI Color Codes for terminal UI
BLUE   := \033[34m
GREEN  := \033[32m
RED    := \033[31m
YELLOW := \033[33m
MAGENTA:= \033[35m
CYAN   := \033[36m
RESET  := \033[0m

.PHONY: all build install uninstall clean test vet lint setup tools-check help dev version check-go install-go

help: ## Show this help message with dynamic target listings
	@echo "Chaathan Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

all: build install setup ## Build, install, and setup all external tools (all-in-one bootstrap)

check-go: ## Verify if Go 1.26+ is installed, automatically running the installer on failure
	@GO_PATH=$$(command -v go 2>/dev/null || echo "/usr/local/go/bin/go"); \
	if [ ! -x "$$GO_PATH" ]; then \
		echo "Go is not installed. Installing Go 1.26+..."; \
		$(MAKE) install-go; \
	else \
		GO_VER=$$("$$GO_PATH" version | awk '{print $$3}' | sed 's/go//'); \
		GO_MAJOR=$$(echo $$GO_VER | cut -d. -f1); \
		GO_MINOR=$$(echo $$GO_VER | cut -d. -f2); \
		if [ $$GO_MAJOR -lt 1 ] || { [ $$GO_MAJOR -eq 1 ] && [ $$GO_MINOR -lt 26 ]; }; then \
			echo "Go version $$GO_VER is too old. Installing Go 1.26+..."; \
			$(MAKE) install-go; \
		fi; \
	fi

install-go: ## Download and install the latest Go binary globally to /usr/local/go
	@if ! command -v curl >/dev/null 2>&1; then \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update -qq && sudo apt-get install -y -qq curl; \
		elif command -v pacman >/dev/null 2>&1; then \
			sudo pacman -S --noconfirm --needed curl; \
		else \
			echo "Please install curl manually"; exit 1; \
		fi; \
	fi
	@ARCH=$$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/') && \
	VER=$$(curl -fsSL https://go.dev/VERSION?m=text | head -n1) && \
	echo "Downloading and installing $$VER ($$ARCH)..." && \
	curl -fsSL "https://go.dev/dl/$${VER}.linux-$${ARCH}.tar.gz" -o /tmp/go.tar.gz && \
	sudo rm -rf /usr/local/go && \
	sudo tar -C /usr/local -xzf /tmp/go.tar.gz && \
	rm -f /tmp/go.tar.gz && \
	(grep -q '/usr/local/go/bin' ~/.bashrc || echo 'export PATH=$$PATH:/usr/local/go/bin' >> ~/.bashrc) && \
	(if [ -f ~/.zshrc ]; then grep -q '/usr/local/go/bin' ~/.zshrc || echo 'export PATH=$$PATH:/usr/local/go/bin' >> ~/.zshrc; fi) && \
	echo "✅ Go installed: $$(/usr/local/go/bin/go version)"

build: check-go ## Build the chaathan binary with version flags
	@printf "$(BLUE)[BUILD]$(RESET) Building $(BINARY_NAME) $(VERSION)...\n"
	@PATH=$$PATH:/usr/local/go/bin $(GO_BIN) build $(GOFLAGS) -o $(BINARY_NAME) .
	@printf "$(GREEN)[BUILD]$(RESET) ✅ Built: ./$(BINARY_NAME)\n"

install: build ## Build and install the chaathan binary to the system path
	@printf "$(BLUE)[INSTALL]$(RESET) Installing to $(INSTALL_DIR)/$(BINARY_NAME)...\n"
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo install -m 0755 $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@printf "$(GREEN)[INSTALL]$(RESET) ✅ Installed: $(INSTALL_DIR)/$(BINARY_NAME)\n"

uninstall: ## Remove the chaathan binary from the system path
	@printf "$(RED)[UNINSTALL]$(RESET) Removing $(INSTALL_DIR)/$(BINARY_NAME)...\n"
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@printf "$(GREEN)[UNINSTALL]$(RESET) ✅ Uninstalled\n"

clean: ## Remove compiled binaries and temporary build artifacts
	@printf "$(YELLOW)[CLEAN]$(RESET) Cleaning...\n"
	@rm -f $(BINARY_NAME) chaathan-flow chaathan-test main coverage.out
	@PATH=$$PATH:/usr/local/go/bin $(GO_BIN) clean
	@printf "$(GREEN)[CLEAN]$(RESET) ✅ Clean completed\n"

test: ## Run the Go unit test suite with race detection and coverage
	@printf "$(MAGENTA)[TEST]$(RESET) Running tests...\n"
	@PATH=$$PATH:/usr/local/go/bin $(GO_BIN) test -race -count=1 -coverpkg=github.com/vishnu303/chaathan/pkg/...,github.com/vishnu303/chaathan/utils/... -coverprofile=coverage.out ./...
	@printf "$(GREEN)[TEST]$(RESET) ✅ Tests passed\n"

vet: ## Run static code analysis with go vet
	@printf "$(CYAN)[VET]$(RESET) Running go vet...\n"
	@PATH=$$PATH:/usr/local/go/bin $(GO_BIN) vet ./...
	@printf "$(GREEN)[VET]$(RESET) ✅ No issues found\n"

lint: ## Run code linting audits with golangci-lint
	@printf "$(YELLOW)[LINT]$(RESET) Running linter...\n"
	@which golangci-lint > /dev/null 2>&1 || (printf "$(RED)[LINT]$(RESET) Install golangci-lint first: https://golangci-lint.run/usage/install/\n" && exit 1)
	@golangci-lint run ./...
	@printf "$(GREEN)[LINT]$(RESET) ✅ Lint passed\n"

setup: build ## Build and execute the environment installer for third-party tools
	@printf "$(GREEN)[SETUP]$(RESET) Running tool setup...\n"
	@./$(BINARY_NAME) setup
	@printf "$(GREEN)[SETUP]$(RESET) ✅ Setup complete\n"

tools-check: build ## Verify the path installation status of all 30 external tools
	@./$(BINARY_NAME) tools check

dev: build ## Run status check command under development mode
	@./$(BINARY_NAME) status

version: build ## Print compile-time build version details
	@./$(BINARY_NAME) version
