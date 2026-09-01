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
# EMBED_CA=1 adds the embedca build tag, which embeds the Mozilla root
# bundle (golang.org/x/crypto/x509roots/fallback) in both binaries. It is
# the default: both binaries reach the dhtproxy over HTTPS, and the roots
# activate only when the system provides no certificate store, so they are
# inert on an image that has ca-bundle and cost about 128 KiB of a mips
# binary (see the size table in README.md). Set EMBED_CA=0 to leave them
# out.
EMBED_CA ?= 1
# PREFIX and BINDIR name the install location, used by the install target
# below.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
# UNITDIR names where the systemd unit is installed.
UNITDIR ?= /etc/systemd/system
# DESTDIR is prepended to every install path, for staged (packaging)
# installs. Empty by default, so a plain "make install" writes to the
# real BINDIR/UNITDIR.
DESTDIR ?=
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

# AGENT_TAGS adds builtin_all to whatever CA_TAG carries. stunmesh-agent
# embeds stunmesh-go's app package (see CLAUDE.md), which links its builtin
# plugins (opendht, cloudflare) only under a builtin_<name> or builtin_all
# build tag; without one, every stub registers nothing and the agent fails
# at runtime with "builtin plugin not found: opendht". stunmesh-provd does
# not embed stunmesh-go, so it keeps TAGS_FLAGS/CA_TAG only.
AGENT_TAGS = builtin_all$(if $(CA_TAG), $(CA_TAG),)
AGENT_TAGS_FLAGS = -tags '$(AGENT_TAGS)'

GO_FLAGS = -ldflags '$(LDFLAGS)' $(TRIMPATH_FLAGS) $(TAGS_FLAGS)
AGENT_GO_FLAGS = -ldflags '$(LDFLAGS)' $(TRIMPATH_FLAGS) $(AGENT_TAGS_FLAGS)

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
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOMIPS=$(GOMIPS) go build $(AGENT_GO_FLAGS) -v -o $(DIST)/$(APP_AGENT) ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT))
endif

# agent-mips and agent-mipsle build the agent for 32-bit MIPS routers with no
# FPU. agent-arm64 builds the agent for 64-bit ARM routers.
.PHONY: agent-mips
agent-mips:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mips GOMIPS=softfloat go build $(AGENT_GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-mips ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-mips)
endif

.PHONY: agent-mipsle
agent-mipsle:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build $(AGENT_GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-mipsle ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-mipsle)
endif

.PHONY: agent-arm64
agent-arm64:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 go build $(AGENT_GO_FLAGS) -v -o $(DIST)/$(APP_AGENT)-linux-arm64 ./cmd/stunmesh-agent
ifneq ($(UPX),0)
	$(call maybe-upx,$(DIST)/$(APP_AGENT)-linux-arm64)
endif

.PHONY: test
test: test-openwrt
	go test ./...

# test-openwrt runs the contrib/openwrt shell tests (see
# contrib/openwrt/tests/run.sh for what they cover and how). It has no
# Go dependency and needs no root.
.PHONY: test-openwrt
test-openwrt:
	sh contrib/openwrt/tests/run.sh

# vet runs go vet for the host GOOS/GOARCH, plus a second pass for
# linux/mips (softfloat). Both passes carry the same build tags as a
# build, so the files behind EMBED_CA's embedca tag are checked too. go vet compiles every package it checks,
# including test-free ones that `go build` alone would not reach, so
# this catches 32-bit build breaks (e.g. an untyped 64-bit constant
# overflowing `int`) that only show up under a 32-bit GOARCH.
# Each pass runs twice more: once with TAGS_FLAGS (what stunmesh-provd
# builds with) and once with AGENT_TAGS_FLAGS (what stunmesh-agent builds
# with, adding builtin_all), so every builtin plugin code path is vetted
# too.
.PHONY: vet
vet:
	go vet $(TAGS_FLAGS) ./...
	go vet $(AGENT_TAGS_FLAGS) ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go vet $(TAGS_FLAGS) ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go vet $(AGENT_TAGS_FLAGS) ./...

# lint runs the golangci-lint already on $PATH, for a developer to check
# locally before pushing. It does not pin a version, so it can drift from
# the version CI's golangci-lint-action installs (see
# .github/actions/lint); install golangci-lint yourself to use this
# target. CI does not call it -- it uses the official action directly,
# which owns golangci-lint's own install/cache/annotation behaviour.
.PHONY: lint
lint:
	golangci-lint run

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

.PHONY: install
install: provd
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(DIST)/$(APP_PROVD) $(DESTDIR)$(BINDIR)/$(APP_PROVD)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 contrib/systemd/stunmesh-provd.service $(DESTDIR)$(UNITDIR)/stunmesh-provd.service
	@echo "Installed $(APP_PROVD) to $(DESTDIR)$(BINDIR) and its systemd unit to $(DESTDIR)$(UNITDIR)."
	@echo "See contrib/systemd/README.md for the remaining setup steps."

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
	@echo "  test          run the contrib/openwrt shell tests, then go test ./..."
	@echo "  test-openwrt  run only the contrib/openwrt shell tests"
	@echo "  vet           run go vet ./..., plus linux/mips (softfloat)"
	@echo "  lint          run golangci-lint (must be installed locally)"
	@echo "  fmt-check     fail if gofmt would change any file"
	@echo "  tidy-check    fail if go mod tidy would change go.mod/go.sum"
	@echo "  upx           compress dist binaries, set UPX=1"
	@echo "  size          list dist binaries and their sizes"
	@echo "  install       install stunmesh-provd and its systemd unit"
	@echo "                (see contrib/systemd/README.md)"
	@echo "  clean         remove the dist directory"
	@echo ""
	@echo "Variables: VERSION GOOS GOARCH STRIP TRIMPATH UPX EXTRA_MIN EMBED_CA"
	@echo "           PREFIX BINDIR UNITDIR DESTDIR"
