FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -X github.com/rosenhouse-bot-sandbox/kglance/internal/version.tag=$VERSION" -o /kglance ./cmd/kglance

# The collector runs as uid 0 (set by the DaemonSet) to read /proc of other processes.
FROM gcr.io/distroless/static:latest
COPY --from=build /kglance /kglance
ENTRYPOINT ["/kglance"]
