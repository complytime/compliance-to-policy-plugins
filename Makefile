# ==============================================================================
# Monorepo Makefile
# Assisted by: Gemini 2.5 Pro
# ==============================================================================
# This Makefile automates common tasks for a Go monorepo with multiple modules.
# It assumes a structure where each application is a module with its main
# package located in a 'cmd/' subdirectory.
#
# Usage:
#   make all         - Runs tests and then builds all binaries
#   make test        - Runs tests for all modules
#   make build       - Builds all binaries and places them in the ./bin directory
#   make clean       - Removes generated binaries and build artifacts
#   make help        - Displays this help message
# ==============================================================================

# Define a list of your Go modules.
# Add or remove modules here as your project evolves.
# The path should be relative to the Makefile's location.
PLUGINS := ./opa-plugin

# The directory where the compiled binaries will be placed.
BIN_DIR := bin

# The default target. Running 'make' with no arguments will execute this.
all: test build

# Phony targets don't correspond to actual files, so 'make' always runs them.
.PHONY: all test build clean help

workspace: ## Setup a go workspace with all modules
		@go work init && go work use $(PLUGINS)
.PHONY: workspace

# ------------------------------------------------------------------------------
# Test Target
# Runs unit tests for every module in the monorepo.
# ------------------------------------------------------------------------------
test: ## Run unit tests
	@for m in $(PLUGINS); do \
		(cd $$m && go test -v ./...); \
		if [ $$? -ne 0 ]; then \
			echo "Tests failed for plugins: $$m"; \
			exit 1; \
		fi; \
	done
	@echo "--- All tests passed! ---"

# ------------------------------------------------------------------------------
# Build Target
# Builds a binary for each module and places it in the $(BIN_DIR) directory.
# ------------------------------------------------------------------------------
build: ## Build binaries
	@mkdir -p $(BIN_DIR)
	@for m in $(PLUGINS); do \
    		(cd $$m && go build -v -o ../$(BIN_DIR)/ ./... ); \
    		if [ $$? -ne 0 ]; then \
    			echo "Build failed for module: $$m"; \
    			exit 1; \
    		fi; \
    done
	@echo "--- All binaries built successfully ---"


clean: ## Clean build artifacts
	@echo "--- Cleaning up build artifacts ---"
	@rm -rf $(BIN_DIR)
	@go clean -modcache
	@echo "--- Cleanup complete ---"

# ------------------------------------------------------------------------------
# Help Target
# Prints a friendly help message.
# ------------------------------------------------------------------------------
help: ## Display this help screen
	@grep -E '^[a-z.A-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
