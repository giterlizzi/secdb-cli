MODULE      := github.com/giterlizzi/secdb-cli
BIN_DIR     := bin
DIST_DIR    := dist
CGO_ENABLED := 0

VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0)
COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BRANCH      := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
BUILD_DATE  := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

ALLOWED_LICENSES := MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,Unlicense
 
LDFLAGS := -X '$(MODULE)/internal/meta.Version=$(VERSION)' \
           -X '$(MODULE)/internal/meta.CommitHash=$(COMMIT_HASH)' \
           -X '$(MODULE)/internal/meta.Branch=$(BRANCH)' \
           -X '$(MODULE)/internal/meta.BuildDate=$(BUILD_DATE)'

.PHONY: all build release vet test coverage spdx-headers clean
.PHONY: install-govulncheck govulncheck
.PHONY: install-go-licenses notice check-licenses
.PHONY: install-goreleaser goreleaser-build goreleaser-snapshot
.PHONY: install-golangci-lint lint

all: test build ## Run tests and build the binary

build: ## Build the secdb binary into bin/
	@mkdir -p $(BIN_DIR)
	@echo "==> building secdb ($(VERSION), $(COMMIT_HASH))"
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/secdb .

release: test ## Run tests, then build a release binary (go build -a)
	@mkdir -p $(BIN_DIR)
	@echo "==> building secdb release ($(VERSION), $(COMMIT_HASH))"
	CGO_ENABLED=$(CGO_ENABLED) go build -a -ldflags "$(LDFLAGS) -s -w" -o $(BIN_DIR)/secdb .

vet: ## Run go vet over the whole module
	go vet ./...

test: ## Run all tests with coverage (writes coverage.out)
	CGO_ENABLED=$(CGO_ENABLED) go test ./... -v -cover -count=1 -coverprofile=coverage.out

coverage: ## Print the test coverage report from coverage.out
	go tool cover -func=coverage.out

install-govulncheck: ## Install govulncheck if not already installed
	command -v govulncheck > /dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest

govulncheck: install-govulncheck ## Scan dependencies for known vulnerabilities
	govulncheck ./...

install-go-licenses: ## Install go-licenses if not already installed
	command -v go-licenses > /dev/null || go install github.com/google/go-licenses@latest

notice: install-go-licenses ## Regenerate the THIRD-PARTY-NOTICES.md file with third-party license attributions
	@echo "==> generating THIRD-PARTY-NOTICES.md"
	go-licenses report --template=build/licenses-notice.tmpl ./... > THIRD-PARTY-NOTICES.md

check-licenses: install-go-licenses ## Fail if a dependency uses a disallowed license
	go-licenses check --allowed_licenses=$(ALLOWED_LICENSES) ./...

spdx-headers: ## Add a missing SPDX-License-Identifier header to any .go file
	@for f in $$(find . -name "*.go" -not -path "./vendor/*"); do \
		if ! grep -q "SPDX-License-Identifier" "$$f"; then \
			{ echo "// SPDX-License-Identifier: Apache-2.0"; echo ""; cat "$$f"; } > "$$f.tmp" && mv "$$f.tmp" "$$f"; \
			echo "updated: $$f"; \
		fi; \
	done

install-goreleaser: ## Install goreleaser if not already installed
	command -v goreleaser > /dev/null || go install github.com/goreleaser/goreleaser/v2@latest

goreleaser-snapshot: install-goreleaser ## Build a local snapshot release (no publish)
	goreleaser build --snapshot --clean

goreleaser-build: install-goreleaser ## Build a release with goreleaser
	goreleaser build --clean

install-golangci-lint: ## Install golangci-lint if not already installed
	command -v golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint: install-golangci-lint ## Run golangci-lint over the whole module
	golangci-lint run ./...

clean: ## Remove build artifacts (bin/ and dist/)
	rm -rf $(BIN_DIR) $(DIST_DIR)

.PHONY: help
help: ## Show help for each of the Makefile recipes
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'
