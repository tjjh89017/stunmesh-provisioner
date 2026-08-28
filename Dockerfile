# This image ships stunmesh-provd only. The agent binary is not a daemon
# (contrib/openwrt runs it from cron/hotplug) and never runs in a
# container, so it has no image of its own.

FROM --platform=$BUILDPLATFORM golang:latest AS builder

ARG TARGETOS
ARG TARGETARCH

# VERSION is stamped into the binary via the Makefile's -X main.version
# ldflag. It cannot be derived with "git describe" inside this build
# context: a container build commonly runs from a shallow clone, a tag-less
# checkout, or a source tarball with no ".git" directory at all, so the
# Makefile's own git-describe fallback is not reliable here. The caller
# (the release workflow, or a manual "docker build") passes the real
# version explicitly; an unset ARG defaults to "dev", matching the
# Makefile's own default when it cannot find a tag.
ARG VERSION=dev

WORKDIR /work
COPY . .

# Cross-compile on the build platform (BUILDPLATFORM), producing a binary
# for the target platform (TARGETOS/TARGETARCH) that buildx requests for
# each entry in --platform. The Makefile already defaults CGO_ENABLED=0,
# EMBED_CA=1, and -s -w -trimpath; only GOOS/GOARCH/VERSION need passing
# through here.
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} make VERSION=${VERSION} provd

FROM scratch

WORKDIR /app

# FROM scratch is safe for this binary specifically, for two reasons:
#   - CGO_ENABLED=0 makes it fully static, so it needs no libc from the
#     base image.
#   - EMBED_CA=1 (the Makefile default) links in the Mozilla root bundle
#     via cmd/stunmesh-provd/embedca.go, so HTTPS to the dhtproxy servers
#     works with no /etc/ssl/certs in the image at all.
# Neither holds for an arbitrary Go binary; both are load-bearing here.
COPY --from=builder /work/dist/stunmesh-provd /app/stunmesh-provd

# The only state stunmesh-provd owns is the --dir tree (default
# /etc/stunmesh/provd, internal/store): the controller identity key and
# every tunnel's private key live under it. Mount a real volume there --
# an anonymous volume loses every key on "docker rm", and a fresh identity
# key on restart cannot decrypt what the old identity published.
VOLUME ["/etc/stunmesh/provd"]

# ENTRYPOINT fixes the binary; CMD supplies only the default command, so
# "docker run <image>" starts the republish loop (publish with no --once,
# PLAN.md 7: runs until SIGINT/SIGTERM) while "docker run <image> init ns"
# or "docker run <image> node add ns id" still reach the same binary with
# their own arguments in place of "publish".
ENTRYPOINT ["/app/stunmesh-provd"]
CMD ["publish"]
