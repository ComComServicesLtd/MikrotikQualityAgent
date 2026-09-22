# syntax=docker/dockerfile:1.7
#
# The controller is not latency-critical and runs on ordinary infrastructure,
# so unlike the agent it has no exotic constraints — but a static binary on a
# minimal base is still the least to keep patched.

FROM golang:1.23-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download || true

COPY . .

# CGO off gives a static binary; trimpath and -s -w drop build paths and debug
# symbols so the image carries nothing about the build host.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /controller ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /controller /controller
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/controller"]
