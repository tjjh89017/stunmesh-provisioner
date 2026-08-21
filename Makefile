# require GNU Make

# APP_PROVD and APP_AGENT name the two binaries.
APP_PROVD ?= stunmesh-provd
APP_AGENT ?= stunmesh-agent
# GOOS and GOARCH default to the host platform.
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
# 32-bit MIPS routers commonly lack an FPU, so default both endians to
# soft-float. Set GOMIPS=hardfloat to override.
ifneq ($(filter mips mipsle,$(GOARCH)),)
GOMIPS ?= softfloat
endif
# STRIP=1 drops symbol and debug info from the binary.
STRIP ?= 1
# TRIMPATH=1 removes local file system paths from the binary.
TRIMPATH ?= 1
# UPX=1 compresses the binary after build. Requires the upx tool.
UPX ?= 0
# EXTRA_MIN=1 forces the smallest binary: strip, trimpath, and upx all on.
EXTRA_MIN ?= 0
# EMBED_CA=1 adds the embedca build tag. This repository has no embedca code
# yet; the tag is a placeholder for a future Mozilla root bundle embed.
EMBED_CA ?= 0
# PREFIX and BINDIR name the install location. Not used by any target yet;
# kept for parity with the stunmesh-go Makefile.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
# VERSION is stamped into each binary via -X main.version.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# DIST is the output directory for all built binaries.
DIST ?= dist

ifneq ($(EXTRA_MIN),0)
	STRIP = 1
	TRIMPATH = 1
	UPX = 1
endif

LDFLAGS = -X main.version=$(VERSION)
ifneq ($(STRIP),0)
	LDFLAGS := -s -w $(LDFLAGS)
endif

TRIMPATH_FLAGS =
ifneq ($(TRIMPATH),0)
	TRIMPATH_FLAGS := -trimpath
endif

CA_TAG =
ifneq ($(EMBED_CA),0)
	CA_TAG := embedca
endif
TAGS_FLAGS = $(if $(CA_TAG),-tags '$(CA_TAG)',)

GO_FLAGS = -ldflags '$(LDFLAGS)' $(TRIMPATH_FLAGS) $(TAGS_FLAGS)

# CGO_ENABLED is always 0. Both binaries are static, with no cgo dependency.
CGO_ENABLED = 0

# maybe-upx compresses the binary path(s) given as $(1) with upx, when
# UPX=1. It fails with a clear message if the upx tool is not installed.
# Callers guard the call with "ifneq ($(UPX),0)" so a plain "make -n"
# prints no upx line at all.
define maybe-upx
@command -v upx >/dev/null 2>&1 || { echo "upx: tool not found, install upx to use UPX=1"; exit 1; }
upx --lzma --best $(1)
endef

.PHONY: all
all: build

.PHONY: build
build: provd agent

.PHONY: provd
provd:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOMIPS=$(GOMIPS) go build $(GO_FLAGS) -v -o $(DIST)/$(APP_PROVD) ./cmd/stunmesh-provd
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_PROVD))
endif

.PHONY: agent
agent:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOMIPS=$(GOMIPS) go build $(GO_FLAGS) -v -o $(DIST)/$(APP_AGENT) ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT))
endif

# agent-mips and agent-mipsle build the agent for 32-bit MIPS routers with no
# FPU. agent-arm64 builds the agent for 64-bit ARM routers.
.PHONY: agent-mips
agent-mips:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mips GOMIPS=softfloat go build $(GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-mips ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-mips)
endif

.PHONY: agent-mipsle
agent-mipsle:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build $(GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-mipsle ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-mipsle)
endif

.PHONY: agent-arm64
agent-arm64:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 go build $(GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-arm64 ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-arm64)
endif

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

# fmt-check fails if any file is not gofmt-formatted. It changes no file.
.PHONY: fmt-check
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt found unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

# tidy-check fails if go mod tidy would change go.mod or go.sum. It uses
# -diff so it never writes to the real module files.
.PHONY: tidy-check
tidy-check:
	go mod tidy -diff

.PHONY: clean
clean:
	rm -rf $(DIST)

# upx compresses every binary currently in $(DIST) in place, using the same
# maybe-upx macro as the build targets so it cannot drift from them. It runs
# only when UPX=1, and it fails with a clear message if upx is not
# installed.
.PHONY: upx
upx:
ifneq ($(UPX),0)
	$(call maybe-upx,$(wildcard $(DIST)/*))
else
	@echo "upx: skipped, set UPX=1 to enable"
endif

# size lists the built binaries so their sizes can be recorded, for example
# in the README.
.PHONY: size
size:
	ls -l $(DIST)/

.PHONY: help
help:
	@echo "Targets:"
	@echo "  all           build both binaries (default)"
	@echo "  build         build both binaries for GOOS/GOARCH"
	@echo "  provd         build stunmesh-provd only"
	@echo "  agent         build stunmesh-agent only"
	@echo "  agent-mips    build stunmesh-agent for linux/mips (softfloat)"
	@echo "  agent-mipsle  build stunmesh-agent for linux/mipsle (softfloat)"
	@echo "  agent-arm64   build stunmesh-agent for linux/arm64"
	@echo "  test          run go test ./..."
	@echo "  vet           run go vet ./..."
	@echo "  fmt-check     fail if gofmt would change any file"
	@echo "  tidy-check    fail if go mod tidy would change go.mod/go.sum"
	@echo "  upx           compress dist binaries, set UPX=1"
	@echo "  size          list dist binaries and their sizes"
	@echo "  clean         remove the dist directory"
	@echo ""
	@echo "Variables: VERSION GOOS GOARCH STRIP TRIMPATH UPX EXTRA_MIN EMBED_CA"
