ARG GO_VERSION=1.25.0
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS base

WORKDIR /app

################################################################################
FROM base AS server-deps

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod/ \
    go list -f '{{if not .TestImports}}{{.ImportPath}}{{end}}' ./... > /dev/null 2>&1 || true && \
    go mod download && \
    rm -rf /go/pkg/mod/cache/download/github.com/stretchr/testify* || true && \
    rm -rf /go/pkg/mod/cache/download/github.com/alicebob/miniredis* || true && \
    rm -rf /go/pkg/mod/cache/download/github.com/pashagolub/pgxmock* || true

################################################################################
FROM base AS test-deps

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod/ \
    go mod download

################################################################################
FROM server-deps AS server-builder

ARG TARGETOS
ARG TARGETARCH

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -trimpath \
    -o /server ./cmd

################################################################################
FROM scratch AS server

COPY --from=server-builder /server /server

USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/server"]

################################################################################
FROM test-deps AS test

ARG TARGETOS=linux
ARG TARGETARCH=arm64
ARG CACHE_BUST

COPY . .

RUN echo "Cache bust: ${CACHE_BUST}"

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go test -v ./internal/service/... ./internal/repository/...
