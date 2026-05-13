BINARY := ./bin/kubesplaining
KIND_CLUSTER_NAME ?= kubesplaining-e2e
KUBECONFIG ?= $(CURDIR)/.tmp/kubeconfig
GOCACHE ?= $(CURDIR)/.tmp/go-build-cache
GOMODCACHE ?= $(CURDIR)/.tmp/go-mod-cache
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)

# Prepend Hermit's bin/ so go, gofmt, rg, kubectl, kind resolve to the pinned
# versions even when the shell has not sourced ./bin/activate-hermit. The shims
# auto-download on first use; nothing is required system-wide.
export PATH := $(CURDIR)/bin:$(PATH)

GOFILES := $(shell $(CURDIR)/bin/rg --files -g '*.go')

# Stamp build metadata into main.{version,commit,date} via -ldflags so
# `kubesplaining version` reports something meaningful for local clones.
# Released binaries get the same vars stamped by GoReleaser at tag time.
# The fallbacks keep the build working when `git` is unavailable (e.g. when
# someone extracts a source tarball on a CI runner that has no .git/).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: setup build test lint e2e scan scan-lp delete clean install-hooks uninstall-hooks

setup:
	$(GOENV) go mod download
	@mkdir -p bin .tmp

build:
	$(GOENV) go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kubesplaining

test:
	$(GOENV) go test ./...

lint:
	@test -z "$$(gofmt -l $(GOFILES))" || (echo "gofmt check failed"; gofmt -l $(GOFILES); exit 1)
	$(GOENV) go vet ./...

install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit .githooks/commit-msg
	@echo "Git hooks installed. Bypass per-commit with: git commit --no-verify"

uninstall-hooks:
	git config --unset core.hooksPath || true
	@echo "Git hooks deactivated for this clone."

e2e: build
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) KUBECONFIG=$(KUBECONFIG) ./scripts/kind-e2e.sh

# Build (which uses the Hermit-managed Go via the PATH prepend above) and then
# scan whatever cluster the current kubectl context points at. Pass extra flags
# via ARGS, e.g. `make scan ARGS="--threshold high --only-modules privesc"`.
scan: build
	$(BINARY) scan $(ARGS)

# Least-privilege focus mode. Requires an audit log: pass its path (file or dir)
# via AUDIT_LOG, plus AUDIT_SOURCE (native|eks, default native) and
# AUDIT_WINDOW_DAYS (default 30). Extra flags ride on ARGS as with `make scan`.
# Example:
#   make scan-lp AUDIT_LOG=./audit.log
#   make scan-lp AUDIT_LOG=./eks-export.json AUDIT_SOURCE=eks AUDIT_WINDOW_DAYS=60 \
#       ARGS="--input-file snapshot.json"
AUDIT_SOURCE ?= native
AUDIT_WINDOW_DAYS ?= 30
scan-lp: build
	@if [ -z "$(AUDIT_LOG)" ]; then \
		echo "AUDIT_LOG is required. Example: make scan-lp AUDIT_LOG=./audit.log"; \
		echo "See docs/audit-logs.md for how to obtain one."; \
		exit 2; \
	fi
	$(BINARY) scan --least-privilege-only \
		--audit-log $(AUDIT_LOG) \
		--audit-source $(AUDIT_SOURCE) \
		--audit-window-days $(AUDIT_WINDOW_DAYS) \
		$(ARGS)

delete:
	kind delete cluster --name $(KIND_CLUSTER_NAME)
	@if [ -f "$(HOME)/.kube/config" ]; then \
		KUBECONFIG="$(HOME)/.kube/config" kind delete cluster --name $(KIND_CLUSTER_NAME) >/dev/null 2>&1 || true; \
	fi

clean:
	rm -rf ./bin ./kubesplaining-report ./.tmp
