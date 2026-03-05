# Chaathan - Pentesting Recon Framework
# Makefile for build, install, and development tasks

BINARY_NAME := chaathan
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOFLAGS := -ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"
INSTALL_DIR := /usr/local/bin

.PHONY: all build install uninstall clean test vet lint setup tools-check help

## help: Show this help message
help:
	@echo "Chaathan Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build the binary"
	@echo "  make install        Build and install to $(INSTALL_DIR)"
	@echo "  make uninstall      Remove from $(INSTALL_DIR)"
	@echo "  make clean          Remove build artifacts"
	@echo "  make test           Run tests"
	@echo "  make vet            Run go vet"
	@echo "  make setup          Install all external tools"
	@echo "  make tools-check    Check which tools are installed"
	@echo "  make all            Build + install + setup"
	@echo ""

## all: Build, install, and setup external tools
all: build install setup

## build: Build the chaathan binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@go build $(GOFLAGS) -o $(BINARY_NAME) .
	@echo "✅ Built: ./$(BINARY_NAME)"

## install: Install chaathan to system path
install: build
	@echo "Installing to $(INSTALL_DIR)/$(BINARY_NAME)..."
	@sudo cp $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Installed: $(INSTALL_DIR)/$(BINARY_NAME)"

## uninstall: Remove chaathan from system path
uninstall:
	@echo "Removing $(INSTALL_DIR)/$(BINARY_NAME)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✅ Uninstalled"

## clean: Remove build artifacts and compiled binaries
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME) chaathan-flow chaathan-test main
	@go clean
	@echo "✅ Clean"

## test: Run all tests
test:
	@echo "Running tests..."
	@go test ./... -v -count=1
	@echo "✅ Tests passed"

## vet: Run go vet for static analysis
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "✅ No issues found"

## lint: Run golangci-lint (install separately)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null 2>&1 || (echo "Install golangci-lint first: https://golangci-lint.run/usage/install/" && exit 1)
	@golangci-lint run ./...
	@echo "✅ Lint passed"

## setup: Install all required external tools
setup: build
	@echo "Running tool setup..."
	@./$(BINARY_NAME) setup
	@echo "✅ Setup complete"

## tools-check: Check which external tools are installed
tools-check: build
	@./$(BINARY_NAME) tools check

## dev: Build and run with sample args for development
dev: build
	@./$(BINARY_NAME) status

## version: Show version info
version: build
	@./$(BINARY_NAME) version
